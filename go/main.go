package main

import (
	"context"
	"database/sql"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/go-mysql-org/go-mysql/client"
	"github.com/go-mysql-org/go-mysql/mysql"
	"github.com/go-mysql-org/go-mysql/replication"
	"github.com/lib/pq"
)

var (
	schemaCacheMu sync.RWMutex
	schemaCache   = make(map[string][]string) // "schema.table" -> []columnNames

	// In-memory mapping lookups
	cardsByPrintingIdMu sync.RWMutex
	cardsByPrintingId   = make(map[string]string) // Postgres printings.id (MySQL card.code) -> canonical card_id slug

	mysqlCardCodesByIdMu sync.RWMutex
	mysqlCardCodesById   = make(map[int64]string) // MySQL card.id (int) -> MySQL card.code (e.g. "01110")

	usernamesByIdMu sync.RWMutex
	usernamesById   = make(map[int64]string) // MySQL user.id (int) -> MySQL user.username (string)

	deckUUIDsByIdMu sync.RWMutex
	deckUUIDsById   = make(map[int64]string) // MySQL deck.id (int) -> MySQL deck.uuid (UUID string)

	decklistUUIDsByIdMu sync.RWMutex
	decklistUUIDsById   = make(map[int64]string) // MySQL decklist.id (int) -> MySQL decklist.uuid (UUID string)

	sideCodesByIdMu sync.RWMutex
	sideCodesById   = make(map[int64]string) // MySQL side.id (int) -> MySQL side.code ("corp"/"runner")

	// Tables with configured replication or in-memory tracking
	supportedReplicationTables = map[string]bool{
		"review":        true,
		"reviewcomment": true,
		"user":          true,
		"card":          true,
		"side":          true,
		"deck":          true,
		"deckslot":      true,
		"deck_card":     true,
		"decklist":      true,
		"decklistslot":  true,
		"decklist_card": true,
	}

	// Tables explicitly ignored that do NOT trigger transaction aborts
	ignoredTables = map[string]bool{
		"deckchange": true,
	}
)

func getEnv(key, defaultVal string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultVal
}

func getEnvInt(key string, defaultVal int) int {
	if val := os.Getenv(key); val != "" {
		if i, err := strconv.Atoi(val); err == nil {
			return i
		}
	}
	return defaultVal
}

func getEnvUint(key string, defaultVal uint) uint {
	if val := os.Getenv(key); val != "" {
		if i, err := strconv.ParseUint(val, 10, 32); err == nil {
			return uint(i)
		}
	}
	return defaultVal
}

// ── Transaction Buffering & Validation ───────────────────────────────────────

type Mutation struct {
	Table       string
	Action      string // "INSERT", "UPDATE", "DELETE"
	Description string
	ApplyPG     func(ctx context.Context, tx *sql.Tx) error
	ApplyMem    func()
}

type TransactionContext struct {
	InTransaction       bool
	XID                 uint64
	LogPos              uint32
	Mutations           []Mutation
	HasUnsupportedTable bool
	UnsupportedTables   map[string]bool
	IgnoredChanges      []string

	// Intra-transaction local lookups for newly inserted entities in the same transaction
	LocalDeckUUIDs     map[int64]string
	LocalDecklistUUIDs map[int64]string
	LocalUsernames     map[int64]string
	LocalCardCodes     map[int64]string
}

func newTransactionContext(inTransaction bool, logPos uint32) *TransactionContext {
	return &TransactionContext{
		InTransaction:      inTransaction,
		LogPos:             logPos,
		UnsupportedTables:  make(map[string]bool),
		LocalDeckUUIDs:     make(map[int64]string),
		LocalDecklistUUIDs: make(map[int64]string),
		LocalUsernames:     make(map[int64]string),
		LocalCardCodes:     make(map[int64]string),
	}
}

func (txCtx *TransactionContext) AddMutation(m Mutation) {
	txCtx.Mutations = append(txCtx.Mutations, m)
}

func (txCtx *TransactionContext) AddUnsupported(table, action, changeSummary string) {
	txCtx.HasUnsupportedTable = true
	txCtx.UnsupportedTables[table] = true
	msg := fmt.Sprintf("[%s %s] %s", table, action, changeSummary)
	txCtx.IgnoredChanges = append(txCtx.IgnoredChanges, msg)
	log.Printf("⚠️ [Ignored Change] Table '%s' does not have replication configured. Action: %s | %s",
		table, action, changeSummary)
}

func (txCtx *TransactionContext) Commit(ctx context.Context, xid uint64, pgDB *sql.DB) {
	// If any part of the transaction touched an unsupported table, abort all writes to avoid partial/incomplete state
	if txCtx.HasUnsupportedTable {
		var unsupportedList []string
		for t := range txCtx.UnsupportedTables {
			unsupportedList = append(unsupportedList, t)
		}
		log.Printf("\n🛑 ─────────────────────────────────────────────────────────────")
		log.Printf("🛑 [Transaction Incomplete - All Writes Skipped]")
		log.Printf("   Transaction XID=%d (LogPos=%d) touched unconfigured table(s): [%s]",
			xid, txCtx.LogPos, strings.Join(unsupportedList, ", "))
		log.Printf("   Total skipped operations in this transaction: %d", len(txCtx.Mutations)+len(txCtx.IgnoredChanges))
		for idx, ignored := range txCtx.IgnoredChanges {
			log.Printf("   • Ignored #%d: %s", idx+1, ignored)
		}
		log.Printf("🛑 ─────────────────────────────────────────────────────────────\n")
		return
	}

	if len(txCtx.Mutations) == 0 {
		return
	}

	// Separate PostgreSQL writes and in-memory updates
	var pgMutations []Mutation
	var memMutations []Mutation
	for _, m := range txCtx.Mutations {
		if m.ApplyPG != nil {
			pgMutations = append(pgMutations, m)
		}
		if m.ApplyMem != nil {
			memMutations = append(memMutations, m)
		}
	}

	// Execute PostgreSQL transaction atomically
	if len(pgMutations) > 0 {
		tx, err := pgDB.BeginTx(ctx, nil)
		if err != nil {
			log.Printf("❌ [Transaction Error] Failed to begin PostgreSQL transaction (XID=%d): %v", xid, err)
			return
		}

		for _, m := range pgMutations {
			if err := m.ApplyPG(ctx, tx); err != nil {
				_ = tx.Rollback()
				log.Printf("❌ [Transaction Rollback] Error executing %s on '%s' (XID=%d): %v", m.Action, m.Table, xid, err)
				return
			}
		}

		if err := tx.Commit(); err != nil {
			log.Printf("❌ [Transaction Commit Error] Failed to commit PostgreSQL transaction (XID=%d): %v", xid, err)
			return
		}

		log.Printf("✅ [Transaction Committed] XID=%d | Replicated %d writes to PostgreSQL atomically.", xid, len(pgMutations))
	}

	// Apply in-memory state updates only after successful transaction commit
	for _, m := range memMutations {
		m.ApplyMem()
	}
}

func main() {
	// ── 1. Configuration (Flags & Environment Variables) ───────────────────────
	mysqlHostFlag := flag.String("mysql-host", getEnv("MYSQL_HOST", "db"), "MySQL host")
	mysqlPortFlag := flag.Int("mysql-port", getEnvInt("MYSQL_PORT", 3306), "MySQL port")
	mysqlUserFlag := flag.String("mysql-user", getEnv("MYSQL_USER", "root"), "MySQL user")
	mysqlPassFlag := flag.String("mysql-password", getEnv("MYSQL_PASSWORD", "passwd"), "MySQL password")
	mysqlDBFlag := flag.String("mysql-db", getEnv("MYSQL_DATABASE", "nrdb-dev"), "MySQL database name")
	mysqlServerIDFlag := flag.Uint("mysql-server-id", getEnvUint("MYSQL_SERVER_ID", 100), "MySQL slave ServerID")

	pgHostFlag := flag.String("pg-host", getEnv("PG_HOST", "postgres"), "Postgres host")
	pgPortFlag := flag.Int("pg-port", getEnvInt("PG_PORT", 5432), "Postgres port")
	pgUserFlag := flag.String("pg-user", getEnv("PG_USER", "postgres"), "Postgres user")
	pgPassFlag := flag.String("pg-password", getEnv("PG_PASSWORD", "postgres"), "Postgres password")
	pgDBFlag := flag.String("pg-db", getEnv("PG_DATABASE", "nrdb_api_development"), "Postgres database name")
	pgSSLFlag := flag.String("pg-sslmode", getEnv("PG_SSLMODE", "disable"), "Postgres SSL mode")

	flag.Parse()

	mysqlHost := *mysqlHostFlag
	mysqlPort := *mysqlPortFlag
	mysqlUser := *mysqlUserFlag
	mysqlPassword := *mysqlPassFlag
	mysqlDBName := *mysqlDBFlag
	mysqlServerID := uint32(*mysqlServerIDFlag)

	pgHost := *pgHostFlag
	pgPort := *pgPortFlag
	pgUser := *pgUserFlag
	pgPassword := *pgPassFlag
	pgDatabase := *pgDBFlag
	pgSSLMode := *pgSSLFlag

	// ── 2. Connect to MySQL ──────────────────────────────────────────────────
	log.Printf("Connecting to MySQL at %s:%d (database: '%s', user: '%s', slave ServerID: %d)...",
		mysqlHost, mysqlPort, mysqlDBName, mysqlUser, mysqlServerID)
	mysqlAddr := fmt.Sprintf("%s:%d", mysqlHost, mysqlPort)

	var mysqlConn *client.Conn
	var err error
	for i := 0; i < 15; i++ {
		connTest, dialErr := net.DialTimeout("tcp", mysqlAddr, 3*time.Second)
		if dialErr != nil {
			log.Printf("Waiting for MySQL port to become reachable (%s): %v...", mysqlAddr, dialErr)
			time.Sleep(2 * time.Second)
			continue
		}
		connTest.Close()

		mysqlConn, err = client.Connect(mysqlAddr, mysqlUser, mysqlPassword, mysqlDBName)
		if err == nil {
			break
		}
		log.Printf("Waiting for MySQL authentication / database readiness (%s): %v...", mysqlAddr, err)
		time.Sleep(2 * time.Second)
	}
	if err != nil {
		log.Fatalf("Failed to connect to MySQL: %v", err)
	}
	defer mysqlConn.Close()
	log.Printf("✅ Successfully connected to MySQL database '%s'.", mysqlDBName)

	// ── 3. Connect to PostgreSQL ─────────────────────────────────────────────
	pgConnStr := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		pgHost, pgPort, pgUser, pgPassword, pgDatabase, pgSSLMode)
	log.Printf("Connecting to PostgreSQL at %s:%d (dbname: '%s', user: '%s')...", pgHost, pgPort, pgDatabase, pgUser)

	pgDB, err := sql.Open("postgres", pgConnStr)
	if err != nil {
		log.Fatalf("Failed to initialize PostgreSQL driver: %v", err)
	}
	defer pgDB.Close()

	pgDB.SetMaxOpenConns(10)
	pgDB.SetMaxIdleConns(5)
	pgDB.SetConnMaxLifetime(5 * time.Minute)

	for i := 0; i < 15; i++ {
		pingCtx, pingCancel := context.WithTimeout(context.Background(), 2*time.Second)
		err = pgDB.PingContext(pingCtx)
		pingCancel()
		if err == nil {
			break
		}
		log.Printf("Waiting for PostgreSQL to become ready (%s:%d): %v...", pgHost, pgPort, err)
		time.Sleep(2 * time.Second)
	}
	if err != nil {
		log.Fatalf("Failed to connect to PostgreSQL: %v", err)
	}
	log.Printf("✅ Successfully connected to PostgreSQL database '%s'.", pgDatabase)

	// ── 4. Preload In-Memory Lookup Maps ─────────────────────────────────────
	initCtx, initCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer initCancel()

	if err := preloadLookupMaps(initCtx, mysqlConn, mysqlDBName, pgDB); err != nil {
		log.Fatalf("Failed to preload lookup maps: %v", err)
	}

	// ── 5. Query Master Binlog Status ────────────────────────────────────────
	res, err := mysqlConn.Execute("SHOW BINARY LOG STATUS")
	if err != nil {
		res, err = mysqlConn.Execute("SHOW MASTER STATUS")
	}

	var currentFile string
	var currentPos uint32

	if err == nil && len(res.Values) > 0 {
		currentFile, _ = res.GetString(0, 0)
		posInt, _ := res.GetInt(0, 1)
		currentPos = uint32(posInt)
		log.Printf("Current MySQL Master Binlog: File=%s, Position=%d", currentFile, currentPos)
	} else {
		log.Printf("Could not determine master status automatically (%v), using defaults.", err)
		currentFile = "mysql-bin.000001"
		currentPos = 4
	}

	if envFile := os.Getenv("BINLOG_FILE"); envFile != "" {
		currentFile = envFile
	}
	if envPos := os.Getenv("BINLOG_POS"); envPos != "" {
		if p, err := strconv.ParseUint(envPos, 10, 32); err == nil {
			currentPos = uint32(p)
		}
	}

	// ── 6. Start Binlog Streamer ─────────────────────────────────────────────
	cfg := replication.BinlogSyncerConfig{
		ServerID: mysqlServerID,
		Flavor:   "mysql",
		Host:     mysqlHost,
		Port:     uint16(mysqlPort),
		User:     mysqlUser,
		Password: mysqlPassword,
	}

	syncer := replication.NewBinlogSyncer(cfg)
	defer syncer.Close()

	log.Printf("Starting binlog sync from File=%s, Pos=%d (Filtering database: '%s') ...",
		currentFile, currentPos, mysqlDBName)
	streamer, err := syncer.StartSync(mysql.Position{Name: currentFile, Pos: currentPos})
	if err != nil {
		log.Fatalf("Failed to start binlog sync: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigChan
		log.Println("Received shutdown signal. Exiting binlog consumer...")
		cancel()
		syncer.Close()
	}()

	log.Printf("Binlog streamer is active. Listening for events on '%s'...", mysqlDBName)

	var currentTx *TransactionContext

	for {
		select {
		case <-ctx.Done():
			return
		default:
			ev, err := streamer.GetEvent(ctx)
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				log.Printf("Error receiving binlog event: %v (reconnecting in 2s...)", err)
				time.Sleep(2 * time.Second)
				continue
			}

			currentTx = handleEvent(ctx, ev, mysqlDBName, currentTx, mysqlConn, pgDB)
		}
	}
}

// preloadLookupMaps initializes mapping tables from Postgres and MySQL on startup.
func preloadLookupMaps(ctx context.Context, mysqlConn *client.Conn, mysqlDB string, pgDB *sql.DB) error {
	log.Println("Preloading lookup maps...")

	// 1. Load cardsByPrintingId from PostgreSQL (printings: id -> card_id)
	rows, err := pgDB.QueryContext(ctx, "SELECT id, card_id FROM printings")
	if err != nil {
		return fmt.Errorf("failed to query Postgres printings: %w", err)
	}
	defer rows.Close()

	cardsByPrintingIdMu.Lock()
	countPrintings := 0
	for rows.Next() {
		var id, cardID string
		if err := rows.Scan(&id, &cardID); err != nil {
			cardsByPrintingIdMu.Unlock()
			return err
		}
		cardsByPrintingId[id] = cardID
		countPrintings++
	}
	cardsByPrintingIdMu.Unlock()
	log.Printf("Loaded %d printings from PostgreSQL into cardsByPrintingId.", countPrintings)

	// Ensure active MySQL database
	if _, err := mysqlConn.Execute(fmt.Sprintf("USE `%s`", mysqlDB)); err != nil {
		return fmt.Errorf("failed to select database '%s': %w", mysqlDB, err)
	}

	// 2. Load MySQL card codes (card: id -> code)
	resCards, err := mysqlConn.Execute(fmt.Sprintf("SELECT id, code FROM `%s`.`card`", mysqlDB))
	if err != nil {
		return fmt.Errorf("failed to query MySQL card table: %w", err)
	}
	mysqlCardCodesByIdMu.Lock()
	for i := 0; i < len(resCards.Values); i++ {
		id, _ := resCards.GetInt(i, 0)
		code, _ := resCards.GetString(i, 1)
		mysqlCardCodesById[id] = code
	}
	countMySQLCards := len(mysqlCardCodesById)
	mysqlCardCodesByIdMu.Unlock()
	log.Printf("Loaded %d cards from MySQL (`%s`.card) into mysqlCardCodesById.", countMySQLCards, mysqlDB)

	// 3. Load usernamesById from MySQL (user: id -> username)
	resUsers, err := mysqlConn.Execute(fmt.Sprintf("SELECT id, username FROM `%s`.`user`", mysqlDB))
	if err != nil {
		return fmt.Errorf("failed to query MySQL user table: %w", err)
	}
	usernamesByIdMu.Lock()
	for i := 0; i < len(resUsers.Values); i++ {
		id, _ := resUsers.GetInt(i, 0)
		username, _ := resUsers.GetString(i, 1)
		usernamesById[id] = username
	}
	countUsers := len(usernamesById)
	usernamesByIdMu.Unlock()
	log.Printf("Loaded %d users from MySQL (`%s`.user) into usernamesById.", countUsers, mysqlDB)

	// 4. Load deckUUIDsById from MySQL (deck: id -> uuid)
	resDecks, err := mysqlConn.Execute(fmt.Sprintf("SELECT id, uuid FROM `%s`.`deck`", mysqlDB))
	if err == nil {
		deckUUIDsByIdMu.Lock()
		for i := 0; i < len(resDecks.Values); i++ {
			id, _ := resDecks.GetInt(i, 0)
			u, _ := resDecks.GetString(i, 1)
			if u != "" {
				deckUUIDsById[id] = u
			}
		}
		countDecks := len(deckUUIDsById)
		deckUUIDsByIdMu.Unlock()
		log.Printf("Loaded %d deck UUIDs from MySQL (`%s`.deck) into deckUUIDsById.", countDecks, mysqlDB)
	}

	// 5. Load decklistUUIDsById from MySQL (decklist: id -> uuid)
	resDecklists, err := mysqlConn.Execute(fmt.Sprintf("SELECT id, uuid FROM `%s`.`decklist`", mysqlDB))
	if err == nil {
		decklistUUIDsByIdMu.Lock()
		for i := 0; i < len(resDecklists.Values); i++ {
			id, _ := resDecklists.GetInt(i, 0)
			u, _ := resDecklists.GetString(i, 1)
			if u != "" {
				decklistUUIDsById[id] = u
			}
		}
		countDecklists := len(decklistUUIDsById)
		decklistUUIDsByIdMu.Unlock()
		log.Printf("Loaded %d decklist UUIDs from MySQL (`%s`.decklist) into decklistUUIDsById.", countDecklists, mysqlDB)
	}

	// 6. Load sideCodesById from MySQL (side: id -> code)
	resSides, err := mysqlConn.Execute(fmt.Sprintf("SELECT id, code FROM `%s`.`side`", mysqlDB))
	if err == nil {
		sideCodesByIdMu.Lock()
		for i := 0; i < len(resSides.Values); i++ {
			id, _ := resSides.GetInt(i, 0)
			c, _ := resSides.GetString(i, 1)
			sideCodesById[id] = c
		}
		sideCodesByIdMu.Unlock()
	}

	return nil
}

// handleEvent processes binlog events with transaction-awareness and registry verification.
func handleEvent(ctx context.Context, ev *replication.BinlogEvent, targetSchema string, currentTx *TransactionContext, mysqlConn *client.Conn, pgDB *sql.DB) *TransactionContext {
	switch e := ev.Event.(type) {

	// ── Transaction Boundaries & Queries ─────────────────────────────────────
	case *replication.QueryEvent:
		schema := string(e.Schema)
		if schema != "" && schema != targetSchema {
			return currentTx
		}

		query := strings.TrimSpace(string(e.Query))
		if query == "BEGIN" {
			if currentTx != nil && currentTx.InTransaction {
				currentTx.Commit(ctx, 0, pgDB)
			}
			return newTransactionContext(true, ev.Header.LogPos)
		}

		if query == "COMMIT" {
			if currentTx != nil {
				currentTx.Commit(ctx, 0, pgDB)
			}
			return nil
		}

		if query == "ROLLBACK" {
			log.Printf("↩️ [Transaction Rolled Back in MySQL] LogPos=%d", ev.Header.LogPos)
			return nil
		}

		// DDL statement
		if query != "" {
			fmt.Printf("\n──────────────────────────────────────────────\n")
			fmt.Printf("[Binlog Query/DDL Event] Schema: %s | LogPos: %d\n", schema, ev.Header.LogPos)
			fmt.Printf("➜ QUERY: %s;\n", query)

			schemaCacheMu.Lock()
			schemaCache = make(map[string][]string)
			schemaCacheMu.Unlock()
		}

	// ── Row Mutation Events ──────────────────────────────────────────────────
	case *replication.RowsEvent:
		schema := string(e.Table.Schema)
		if schema != targetSchema {
			return currentTx
		}

		table := string(e.Table.Table)
		colNames := getColumnNames(mysqlConn, schema, table)

		isSingleStatement := false
		if currentTx == nil {
			isSingleStatement = true
			currentTx = newTransactionContext(false, ev.Header.LogPos)
		}

		if supportedReplicationTables[table] {
			switch table {
			case "deck":
				processDeckMutations(currentTx, ev.Header.EventType, colNames, e.Rows)

			case "deckslot", "deck_card":
				processDeckSlotMutations(currentTx, ev.Header.EventType, colNames, e.Rows)

			case "decklist":
				processDecklistMutations(currentTx, ev.Header.EventType, colNames, e.Rows)

			case "decklistslot", "decklist_card":
				processDecklistSlotMutations(currentTx, ev.Header.EventType, colNames, e.Rows)

			case "review":
				processReviewMutations(currentTx, ev.Header.EventType, colNames, e.Rows)

			case "reviewcomment":
				processReviewCommentMutations(currentTx, ev.Header.EventType, colNames, e.Rows)

			case "user":
				processUserMutations(currentTx, ev.Header.EventType, colNames, e.Rows)

			case "card":
				processCardMutations(currentTx, ev.Header.EventType, colNames, e.Rows)

			case "side":
				processSideMutations(currentTx, ev.Header.EventType, colNames, e.Rows)
			}
		} else if ignoredTables[table] {
			changeSummary := buildGenericChangeSummary(table, ev.Header.EventType, colNames, e.Rows)
			log.Printf("ℹ️ [Ignored Table - Safe] Skipping table '%s' (%s): %s", table, formatEventType(ev.Header.EventType), changeSummary)
		} else {
			changeSummary := buildGenericChangeSummary(table, ev.Header.EventType, colNames, e.Rows)
			currentTx.AddUnsupported(table, formatEventType(ev.Header.EventType), changeSummary)
		}

		if isSingleStatement {
			currentTx.Commit(ctx, 0, pgDB)
			return nil
		}

	// ── Transaction Commit (XID Event) ───────────────────────────────────────
	case *replication.XIDEvent:
		if currentTx != nil {
			currentTx.Commit(ctx, e.XID, pgDB)
		}
		return nil
	}

	return currentTx
}

// ── Mutation Builders for Deck & Deck Slots ──────────────────────────────────

func processDeckMutations(txCtx *TransactionContext, eventType replication.EventType, colNames []string, rows [][]interface{}) {
	switch eventType {
	case replication.WRITE_ROWS_EVENTv1, replication.WRITE_ROWS_EVENTv2:
		for _, row := range rows {
			m := getRowMap(colNames, row)
			deckID := getInt64(m["id"])
			uuidStr := getString(m["uuid"])
			name := getString(m["name"])
			notes := getString(m["description"])
			sideID := resolveSideCode(m["side_id"])
			username := resolveUsername(txCtx, m["user_id"])
			identityCardID := resolveCardSlug(txCtx, m["identity_id"])
			followsRules := parseFollowsRules(m["problem"])
			tags := parseTagsArray(m["tags"])
			createdAt := getTime(m["date_creation"])
			updatedAt := getTime(m["date_update"])
			if createdAt.IsZero() {
				createdAt = time.Now()
			}
			if updatedAt.IsZero() {
				updatedAt = createdAt
			}

			if uuidStr == "" {
				log.Printf("⚠️ [Deck Warning] Missing UUID for deck id=%d; skipping.", deckID)
				continue
			}

			// Immediately record in transaction-local map so subsequent deckslot events in the same tx can resolve it
			if txCtx != nil && txCtx.LocalDeckUUIDs != nil {
				txCtx.LocalDeckUUIDs[deckID] = uuidStr
			}

			sqlPreview := fmt.Sprintf("INSERT INTO decks (id='%s', name='%s', user='%s', identity='%s')", uuidStr, name, username, identityCardID)
			txCtx.AddMutation(Mutation{
				Table:       "deck",
				Action:      "INSERT",
				Description: sqlPreview,
				ApplyPG: func(ctx context.Context, tx *sql.Tx) error {
					query := `
						INSERT INTO decks (id, name, notes, side_id, user_id, identity_card_id, follows_basic_deckbuilding_rules, tags, created_at, updated_at)
						VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
						ON CONFLICT (id) DO UPDATE SET
							name = EXCLUDED.name,
							notes = EXCLUDED.notes,
							side_id = EXCLUDED.side_id,
							user_id = EXCLUDED.user_id,
							identity_card_id = EXCLUDED.identity_card_id,
							follows_basic_deckbuilding_rules = EXCLUDED.follows_basic_deckbuilding_rules,
							tags = EXCLUDED.tags,
							updated_at = EXCLUDED.updated_at;
					`
					_, err := tx.ExecContext(ctx, query, uuidStr, name, notes, sideID, username, identityCardID, followsRules, pq.Array(tags), createdAt, updatedAt)
					if err == nil {
						log.Printf("🃏 [Replication: Deck INSERT] UUID='%s' | Name='%s' | User='%s' | Identity='%s'", uuidStr, name, username, identityCardID)
					}
					return err
				},
				ApplyMem: func() {
					deckUUIDsByIdMu.Lock()
					deckUUIDsById[deckID] = uuidStr
					deckUUIDsByIdMu.Unlock()
				},
			})
		}

	case replication.UPDATE_ROWS_EVENTv1, replication.UPDATE_ROWS_EVENTv2:
		for i := 0; i < len(rows); i += 2 {
			newRow := rows[i+1]
			m := getRowMap(colNames, newRow)
			deckID := getInt64(m["id"])
			uuidStr := getString(m["uuid"])
			if uuidStr == "" {
				uuidStr = resolveDeckUUID(txCtx, deckID)
			}
			name := getString(m["name"])
			notes := getString(m["description"])
			sideID := resolveSideCode(m["side_id"])
			username := resolveUsername(txCtx, m["user_id"])
			identityCardID := resolveCardSlug(txCtx, m["identity_id"])
			followsRules := parseFollowsRules(m["problem"])
			tags := parseTagsArray(m["tags"])
			updatedAt := getTime(m["date_update"])
			if updatedAt.IsZero() {
				updatedAt = time.Now()
			}

			if uuidStr != "" && txCtx != nil && txCtx.LocalDeckUUIDs != nil {
				txCtx.LocalDeckUUIDs[deckID] = uuidStr
			}

			sqlPreview := fmt.Sprintf("UPDATE decks SET name='%s', user='%s' WHERE id='%s'", name, username, uuidStr)
			txCtx.AddMutation(Mutation{
				Table:       "deck",
				Action:      "UPDATE",
				Description: sqlPreview,
				ApplyPG: func(ctx context.Context, tx *sql.Tx) error {
					query := `
						UPDATE decks SET
							name = $2,
							notes = $3,
							side_id = $4,
							user_id = $5,
							identity_card_id = $6,
							follows_basic_deckbuilding_rules = $7,
							tags = $8,
							updated_at = $9
						WHERE id = $1;
					`
					_, err := tx.ExecContext(ctx, query, uuidStr, name, notes, sideID, username, identityCardID, followsRules, pq.Array(tags), updatedAt)
					if err == nil {
						log.Printf("🃏 [Replication: Deck UPDATE] UUID='%s' | Name='%s' | User='%s'", uuidStr, name, username)
					}
					return err
				},
				ApplyMem: func() {
					if uuidStr != "" {
						deckUUIDsByIdMu.Lock()
						deckUUIDsById[deckID] = uuidStr
						deckUUIDsByIdMu.Unlock()
					}
				},
			})
		}

	case replication.DELETE_ROWS_EVENTv1, replication.DELETE_ROWS_EVENTv2:
		for _, row := range rows {
			m := getRowMap(colNames, row)
			deckID := getInt64(m["id"])
			uuidStr := getString(m["uuid"])
			if uuidStr == "" {
				uuidStr = resolveDeckUUID(txCtx, deckID)
			}

			sqlPreview := fmt.Sprintf("DELETE FROM decks WHERE id='%s'", uuidStr)
			txCtx.AddMutation(Mutation{
				Table:       "deck",
				Action:      "DELETE",
				Description: sqlPreview,
				ApplyPG: func(ctx context.Context, tx *sql.Tx) error {
					_, err := tx.ExecContext(ctx, "DELETE FROM decks WHERE id = $1;", uuidStr)
					if err == nil {
						log.Printf("🃏 [Replication: Deck DELETE] UUID='%s' (id=%d)", uuidStr, deckID)
					}
					return err
				},
				ApplyMem: func() {
					deckUUIDsByIdMu.Lock()
					delete(deckUUIDsById, deckID)
					deckUUIDsByIdMu.Unlock()
				},
			})
		}
	}
}

func processDeckSlotMutations(txCtx *TransactionContext, eventType replication.EventType, colNames []string, rows [][]interface{}) {
	switch eventType {
	case replication.WRITE_ROWS_EVENTv1, replication.WRITE_ROWS_EVENTv2:
		for _, row := range rows {
			m := getRowMap(colNames, row)
			// Use MySQL deck.uuid as deck_id (UUID) in Postgres decks_cards (checks intra-transaction local map)
			deckUUID := resolveDeckUUID(txCtx, m["deck_id"])
			cardSlug := resolveCardSlug(txCtx, m["card_id"])
			quantity := getInt64(m["quantity"])

			if deckUUID == "" || cardSlug == "" {
				log.Printf("⚠️ [DeckSlot Warning] Unresolved deckUUID='%s' or cardSlug='%s'; skipping slot write.", deckUUID, cardSlug)
				continue
			}

			sqlPreview := fmt.Sprintf("INSERT INTO decks_cards (deck_id='%s', card_id='%s', qty=%d)", deckUUID, cardSlug, quantity)
			txCtx.AddMutation(Mutation{
				Table:       "deckslot",
				Action:      "INSERT",
				Description: sqlPreview,
				ApplyPG: func(ctx context.Context, tx *sql.Tx) error {
					query := `
						INSERT INTO decks_cards (deck_id, card_id, quantity)
						VALUES ($1, $2, $3)
						ON CONFLICT (deck_id, card_id) DO UPDATE SET
							quantity = EXCLUDED.quantity;
					`
					_, err := tx.ExecContext(ctx, query, deckUUID, cardSlug, quantity)
					if err == nil {
						log.Printf("🗂️ [Replication: DeckSlot INSERT] DeckUUID='%s' | Card='%s' | Qty=%d", deckUUID, cardSlug, quantity)
					}
					return err
				},
			})
		}

	case replication.UPDATE_ROWS_EVENTv1, replication.UPDATE_ROWS_EVENTv2:
		for i := 0; i < len(rows); i += 2 {
			oldRow := rows[i]
			newRow := rows[i+1]
			oldM := getRowMap(colNames, oldRow)
			newM := getRowMap(colNames, newRow)

			deckUUID := resolveDeckUUID(txCtx, newM["deck_id"])
			if deckUUID == "" {
				deckUUID = resolveDeckUUID(txCtx, oldM["deck_id"])
			}
			oldCardSlug := resolveCardSlug(txCtx, oldM["card_id"])
			newCardSlug := resolveCardSlug(txCtx, newM["card_id"])
			quantity := getInt64(newM["quantity"])

			sqlPreview := fmt.Sprintf("UPDATE decks_cards SET card_id='%s', qty=%d WHERE deck_id='%s' AND card_id='%s'",
				newCardSlug, quantity, deckUUID, oldCardSlug)
			txCtx.AddMutation(Mutation{
				Table:       "deckslot",
				Action:      "UPDATE",
				Description: sqlPreview,
				ApplyPG: func(ctx context.Context, tx *sql.Tx) error {
					if oldCardSlug != newCardSlug {
						_, _ = tx.ExecContext(ctx, "DELETE FROM decks_cards WHERE deck_id = $1 AND card_id = $2;", deckUUID, oldCardSlug)
					}
					query := `
						INSERT INTO decks_cards (deck_id, card_id, quantity)
						VALUES ($1, $2, $3)
						ON CONFLICT (deck_id, card_id) DO UPDATE SET
							quantity = EXCLUDED.quantity;
					`
					_, err := tx.ExecContext(ctx, query, deckUUID, newCardSlug, quantity)
					if err == nil {
						log.Printf("🗂️ [Replication: DeckSlot UPDATE] DeckUUID='%s' | Card='%s' | Qty=%d", deckUUID, newCardSlug, quantity)
					}
					return err
				},
			})
		}

	case replication.DELETE_ROWS_EVENTv1, replication.DELETE_ROWS_EVENTv2:
		for _, row := range rows {
			m := getRowMap(colNames, row)
			deckUUID := resolveDeckUUID(txCtx, m["deck_id"])
			cardSlug := resolveCardSlug(txCtx, m["card_id"])

			sqlPreview := fmt.Sprintf("DELETE FROM decks_cards WHERE deck_id='%s' AND card_id='%s'", deckUUID, cardSlug)
			txCtx.AddMutation(Mutation{
				Table:       "deckslot",
				Action:      "DELETE",
				Description: sqlPreview,
				ApplyPG: func(ctx context.Context, tx *sql.Tx) error {
					_, err := tx.ExecContext(ctx, "DELETE FROM decks_cards WHERE deck_id = $1 AND card_id = $2;", deckUUID, cardSlug)
					if err == nil {
						log.Printf("🗂️ [Replication: DeckSlot DELETE] DeckUUID='%s' | Card='%s'", deckUUID, cardSlug)
					}
					return err
				},
			})
		}
	}
}

// ── Mutation Builders for Decklist & Decklist Slots ──────────────────────────

func processDecklistMutations(txCtx *TransactionContext, eventType replication.EventType, colNames []string, rows [][]interface{}) {
	switch eventType {
	case replication.WRITE_ROWS_EVENTv1, replication.WRITE_ROWS_EVENTv2:
		for _, row := range rows {
			m := getRowMap(colNames, row)
			decklistID := getInt64(m["id"])
			uuidStr := getString(m["uuid"])
			name := getString(m["name"])
			notes := getReviewBody(m) // description / rawdescription
			sideID := resolveSideCode(m["side_id"])
			username := resolveUsername(txCtx, m["user_id"])
			identityCardID := resolveCardSlug(txCtx, m["identity_id"])
			followsRules := parseFollowsRules(m["problem"])
			tags := parseTagsArray(m["tags"])
			createdAt := getTime(m["date_creation"])
			updatedAt := getTime(m["date_update"])
			if createdAt.IsZero() {
				createdAt = time.Now()
			}
			if updatedAt.IsZero() {
				updatedAt = createdAt
			}

			if uuidStr == "" {
				log.Printf("⚠️ [Decklist Warning] Missing UUID for decklist id=%d; skipping.", decklistID)
				continue
			}

			// Immediately record in transaction-local map
			if txCtx != nil && txCtx.LocalDecklistUUIDs != nil {
				txCtx.LocalDecklistUUIDs[decklistID] = uuidStr
			}

			sqlPreview := fmt.Sprintf("INSERT INTO decklists (id='%s', name='%s', user='%s', identity='%s')", uuidStr, name, username, identityCardID)
			txCtx.AddMutation(Mutation{
				Table:       "decklist",
				Action:      "INSERT",
				Description: sqlPreview,
				ApplyPG: func(ctx context.Context, tx *sql.Tx) error {
					query := `
						INSERT INTO decklists (id, name, notes, side_id, user_id, identity_card_id, follows_basic_deckbuilding_rules, tags, created_at, updated_at)
						VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
						ON CONFLICT (id) DO UPDATE SET
							name = EXCLUDED.name,
							notes = EXCLUDED.notes,
							side_id = EXCLUDED.side_id,
							user_id = EXCLUDED.user_id,
							identity_card_id = EXCLUDED.identity_card_id,
							follows_basic_deckbuilding_rules = EXCLUDED.follows_basic_deckbuilding_rules,
							tags = EXCLUDED.tags,
							updated_at = EXCLUDED.updated_at;
					`
					_, err := tx.ExecContext(ctx, query, uuidStr, name, notes, sideID, username, identityCardID, followsRules, pq.Array(tags), createdAt, updatedAt)
					if err == nil {
						log.Printf("📜 [Replication: Decklist INSERT] UUID='%s' | Name='%s' | User='%s' | Identity='%s'", uuidStr, name, username, identityCardID)
					}
					return err
				},
				ApplyMem: func() {
					decklistUUIDsByIdMu.Lock()
					decklistUUIDsById[decklistID] = uuidStr
					decklistUUIDsByIdMu.Unlock()
				},
			})
		}

	case replication.UPDATE_ROWS_EVENTv1, replication.UPDATE_ROWS_EVENTv2:
		for i := 0; i < len(rows); i += 2 {
			newRow := rows[i+1]
			m := getRowMap(colNames, newRow)
			decklistID := getInt64(m["id"])
			uuidStr := getString(m["uuid"])
			if uuidStr == "" {
				uuidStr = resolveDecklistUUID(txCtx, decklistID)
			}
			name := getString(m["name"])
			notes := getReviewBody(m)
			sideID := resolveSideCode(m["side_id"])
			username := resolveUsername(txCtx, m["user_id"])
			identityCardID := resolveCardSlug(txCtx, m["identity_id"])
			followsRules := parseFollowsRules(m["problem"])
			tags := parseTagsArray(m["tags"])
			updatedAt := getTime(m["date_update"])
			if updatedAt.IsZero() {
				updatedAt = time.Now()
			}

			if uuidStr != "" && txCtx != nil && txCtx.LocalDecklistUUIDs != nil {
				txCtx.LocalDecklistUUIDs[decklistID] = uuidStr
			}

			sqlPreview := fmt.Sprintf("UPDATE decklists SET name='%s', user='%s' WHERE id='%s'", name, username, uuidStr)
			txCtx.AddMutation(Mutation{
				Table:       "decklist",
				Action:      "UPDATE",
				Description: sqlPreview,
				ApplyPG: func(ctx context.Context, tx *sql.Tx) error {
					query := `
						UPDATE decklists SET
							name = $2,
							notes = $3,
							side_id = $4,
							user_id = $5,
							identity_card_id = $6,
							follows_basic_deckbuilding_rules = $7,
							tags = $8,
							updated_at = $9
						WHERE id = $1;
					`
					_, err := tx.ExecContext(ctx, query, uuidStr, name, notes, sideID, username, identityCardID, followsRules, pq.Array(tags), updatedAt)
					if err == nil {
						log.Printf("📜 [Replication: Decklist UPDATE] UUID='%s' | Name='%s' | User='%s'", uuidStr, name, username)
					}
					return err
				},
				ApplyMem: func() {
					if uuidStr != "" {
						decklistUUIDsByIdMu.Lock()
						decklistUUIDsById[decklistID] = uuidStr
						decklistUUIDsByIdMu.Unlock()
					}
				},
			})
		}

	case replication.DELETE_ROWS_EVENTv1, replication.DELETE_ROWS_EVENTv2:
		for _, row := range rows {
			m := getRowMap(colNames, row)
			decklistID := getInt64(m["id"])
			uuidStr := getString(m["uuid"])
			if uuidStr == "" {
				uuidStr = resolveDecklistUUID(txCtx, decklistID)
			}

			sqlPreview := fmt.Sprintf("DELETE FROM decklists WHERE id='%s'", uuidStr)
			txCtx.AddMutation(Mutation{
				Table:       "decklist",
				Action:      "DELETE",
				Description: sqlPreview,
				ApplyPG: func(ctx context.Context, tx *sql.Tx) error {
					_, err := tx.ExecContext(ctx, "DELETE FROM decklists WHERE id = $1;", uuidStr)
					if err == nil {
						log.Printf("📜 [Replication: Decklist DELETE] UUID='%s' (id=%d)", uuidStr, decklistID)
					}
					return err
				},
				ApplyMem: func() {
					decklistUUIDsByIdMu.Lock()
					delete(decklistUUIDsById, decklistID)
					decklistUUIDsByIdMu.Unlock()
				},
			})
		}
	}
}

func processDecklistSlotMutations(txCtx *TransactionContext, eventType replication.EventType, colNames []string, rows [][]interface{}) {
	switch eventType {
	case replication.WRITE_ROWS_EVENTv1, replication.WRITE_ROWS_EVENTv2:
		for _, row := range rows {
			m := getRowMap(colNames, row)
			// Use MySQL decklist.uuid as decklist_id (UUID) in Postgres decklists_cards
			decklistUUID := resolveDecklistUUID(txCtx, m["decklist_id"])
			cardSlug := resolveCardSlug(txCtx, m["card_id"])
			quantity := getInt64(m["quantity"])

			if decklistUUID == "" || cardSlug == "" {
				log.Printf("⚠️ [DecklistSlot Warning] Unresolved decklistUUID='%s' or cardSlug='%s'; skipping slot write.", decklistUUID, cardSlug)
				continue
			}

			sqlPreview := fmt.Sprintf("INSERT INTO decklists_cards (decklist_id='%s', card_id='%s', qty=%d)", decklistUUID, cardSlug, quantity)
			txCtx.AddMutation(Mutation{
				Table:       "decklistslot",
				Action:      "INSERT",
				Description: sqlPreview,
				ApplyPG: func(ctx context.Context, tx *sql.Tx) error {
					query := `
						INSERT INTO decklists_cards (decklist_id, card_id, quantity)
						VALUES ($1, $2, $3)
						ON CONFLICT (decklist_id, card_id) DO UPDATE SET
							quantity = EXCLUDED.quantity;
					`
					_, err := tx.ExecContext(ctx, query, decklistUUID, cardSlug, quantity)
					if err == nil {
						log.Printf("📑 [Replication: DecklistSlot INSERT] DecklistUUID='%s' | Card='%s' | Qty=%d", decklistUUID, cardSlug, quantity)
					}
					return err
				},
			})
		}

	case replication.UPDATE_ROWS_EVENTv1, replication.UPDATE_ROWS_EVENTv2:
		for i := 0; i < len(rows); i += 2 {
			oldRow := rows[i]
			newRow := rows[i+1]
			oldM := getRowMap(colNames, oldRow)
			newM := getRowMap(colNames, newRow)

			decklistUUID := resolveDecklistUUID(txCtx, newM["decklist_id"])
			if decklistUUID == "" {
				decklistUUID = resolveDecklistUUID(txCtx, oldM["decklist_id"])
			}
			oldCardSlug := resolveCardSlug(txCtx, oldM["card_id"])
			newCardSlug := resolveCardSlug(txCtx, newM["card_id"])
			quantity := getInt64(newM["quantity"])

			sqlPreview := fmt.Sprintf("UPDATE decklists_cards SET card_id='%s', qty=%d WHERE decklist_id='%s' AND card_id='%s'",
				newCardSlug, quantity, decklistUUID, oldCardSlug)
			txCtx.AddMutation(Mutation{
				Table:       "decklistslot",
				Action:      "UPDATE",
				Description: sqlPreview,
				ApplyPG: func(ctx context.Context, tx *sql.Tx) error {
					if oldCardSlug != newCardSlug {
						_, _ = tx.ExecContext(ctx, "DELETE FROM decklists_cards WHERE decklist_id = $1 AND card_id = $2;", decklistUUID, oldCardSlug)
					}
					query := `
						INSERT INTO decklists_cards (decklist_id, card_id, quantity)
						VALUES ($1, $2, $3)
						ON CONFLICT (decklist_id, card_id) DO UPDATE SET
							quantity = EXCLUDED.quantity;
					`
					_, err := tx.ExecContext(ctx, query, decklistUUID, newCardSlug, quantity)
					if err == nil {
						log.Printf("📑 [Replication: DecklistSlot UPDATE] DecklistUUID='%s' | Card='%s' | Qty=%d", decklistUUID, newCardSlug, quantity)
					}
					return err
				},
			})
		}

	case replication.DELETE_ROWS_EVENTv1, replication.DELETE_ROWS_EVENTv2:
		for _, row := range rows {
			m := getRowMap(colNames, row)
			decklistUUID := resolveDecklistUUID(txCtx, m["decklist_id"])
			cardSlug := resolveCardSlug(txCtx, m["card_id"])

			sqlPreview := fmt.Sprintf("DELETE FROM decklists_cards WHERE decklist_id='%s' AND card_id='%s'", decklistUUID, cardSlug)
			txCtx.AddMutation(Mutation{
				Table:       "decklistslot",
				Action:      "DELETE",
				Description: sqlPreview,
				ApplyPG: func(ctx context.Context, tx *sql.Tx) error {
					_, err := tx.ExecContext(ctx, "DELETE FROM decklists_cards WHERE decklist_id = $1 AND card_id = $2;", decklistUUID, cardSlug)
					if err == nil {
						log.Printf("📑 [Replication: DecklistSlot DELETE] DecklistUUID='%s' | Card='%s'", decklistUUID, cardSlug)
					}
					return err
				},
			})
		}
	}
}

// ── Mutation Builders for Reviews & Metadata ────────────────────────────────

func processReviewMutations(txCtx *TransactionContext, eventType replication.EventType, colNames []string, rows [][]interface{}) {
	switch eventType {
	case replication.WRITE_ROWS_EVENTv1, replication.WRITE_ROWS_EVENTv2:
		for _, row := range rows {
			m := getRowMap(colNames, row)
			id := getInt64(m["id"])
			cardSlug := resolveCardSlug(txCtx, m["card_id"])
			username := resolveUsername(txCtx, m["user_id"])
			body := getReviewBody(m)
			createdAt := getTime(m["date_creation"])
			updatedAt := getTime(m["date_update"])
			if createdAt.IsZero() {
				createdAt = time.Now()
			}
			if updatedAt.IsZero() {
				updatedAt = createdAt
			}

			sqlPreview := fmt.Sprintf("INSERT INTO reviews (id=%d, card='%s', user='%s')", id, cardSlug, username)
			txCtx.AddMutation(Mutation{
				Table:       "review",
				Action:      "INSERT",
				Description: sqlPreview,
				ApplyPG: func(ctx context.Context, tx *sql.Tx) error {
					query := `
						INSERT INTO reviews (id, card_id, user_id, body, created_at, updated_at)
						VALUES ($1, $2, $3, $4, $5, $6)
						ON CONFLICT (id) DO UPDATE SET
							card_id = EXCLUDED.card_id,
							user_id = EXCLUDED.user_id,
							body = EXCLUDED.body,
							updated_at = EXCLUDED.updated_at;
					`
					_, err := tx.ExecContext(ctx, query, id, cardSlug, username, body, createdAt, updatedAt)
					if err == nil {
						log.Printf("⭐ [Replication: Review INSERT] ID=%d | Card='%s' | User='%s'", id, cardSlug, username)
					}
					return err
				},
			})
		}

	case replication.UPDATE_ROWS_EVENTv1, replication.UPDATE_ROWS_EVENTv2:
		for i := 0; i < len(rows); i += 2 {
			newRow := rows[i+1]
			m := getRowMap(colNames, newRow)
			id := getInt64(m["id"])
			cardSlug := resolveCardSlug(txCtx, m["card_id"])
			username := resolveUsername(txCtx, m["user_id"])
			body := getReviewBody(m)
			updatedAt := getTime(m["date_update"])
			if updatedAt.IsZero() {
				updatedAt = time.Now()
			}

			sqlPreview := fmt.Sprintf("UPDATE reviews SET card='%s', user='%s' WHERE id=%d", cardSlug, username, id)
			txCtx.AddMutation(Mutation{
				Table:       "review",
				Action:      "UPDATE",
				Description: sqlPreview,
				ApplyPG: func(ctx context.Context, tx *sql.Tx) error {
					query := `
						UPDATE reviews SET
							card_id = $2,
							user_id = $3,
							body = $4,
							updated_at = $5
						WHERE id = $1;
					`
					_, err := tx.ExecContext(ctx, query, id, cardSlug, username, body, updatedAt)
					if err == nil {
						log.Printf("⭐ [Replication: Review UPDATE] ID=%d | Card='%s' | User='%s'", id, cardSlug, username)
					}
					return err
				},
			})
		}

	case replication.DELETE_ROWS_EVENTv1, replication.DELETE_ROWS_EVENTv2:
		for _, row := range rows {
			m := getRowMap(colNames, row)
			id := getInt64(m["id"])

			sqlPreview := fmt.Sprintf("DELETE FROM reviews WHERE id=%d", id)
			txCtx.AddMutation(Mutation{
				Table:       "review",
				Action:      "DELETE",
				Description: sqlPreview,
				ApplyPG: func(ctx context.Context, tx *sql.Tx) error {
					_, err := tx.ExecContext(ctx, "DELETE FROM reviews WHERE id = $1;", id)
					if err == nil {
						log.Printf("⭐ [Replication: Review DELETE] ID=%d", id)
					}
					return err
				},
			})
		}
	}
}

func processReviewCommentMutations(txCtx *TransactionContext, eventType replication.EventType, colNames []string, rows [][]interface{}) {
	switch eventType {
	case replication.WRITE_ROWS_EVENTv1, replication.WRITE_ROWS_EVENTv2:
		for _, row := range rows {
			m := getRowMap(colNames, row)
			id := getInt64(m["id"])
			reviewID := getInt64(m["review_id"])
			username := resolveUsername(txCtx, m["user_id"])
			body := getString(m["text"])
			createdAt := getTime(m["date_creation"])
			updatedAt := getTime(m["date_update"])
			if createdAt.IsZero() {
				createdAt = time.Now()
			}
			if updatedAt.IsZero() {
				updatedAt = createdAt
			}

			sqlPreview := fmt.Sprintf("INSERT INTO review_comments (id=%d, review_id=%d, user='%s')", id, reviewID, username)
			txCtx.AddMutation(Mutation{
				Table:       "reviewcomment",
				Action:      "INSERT",
				Description: sqlPreview,
				ApplyPG: func(ctx context.Context, tx *sql.Tx) error {
					query := `
						INSERT INTO review_comments (id, review_id, user_id, body, created_at, updated_at)
						VALUES ($1, $2, $3, $4, $5, $6)
						ON CONFLICT (id) DO UPDATE SET
							review_id = EXCLUDED.review_id,
							user_id = EXCLUDED.user_id,
							body = EXCLUDED.body,
							updated_at = EXCLUDED.updated_at;
					`
					_, err := tx.ExecContext(ctx, query, id, reviewID, username, body, createdAt, updatedAt)
					if err == nil {
						log.Printf("💬 [Replication: ReviewComment INSERT] ID=%d | ReviewID=%d | User='%s'", id, reviewID, username)
					}
					return err
				},
			})
		}

	case replication.UPDATE_ROWS_EVENTv1, replication.UPDATE_ROWS_EVENTv2:
		for i := 0; i < len(rows); i += 2 {
			newRow := rows[i+1]
			m := getRowMap(colNames, newRow)
			id := getInt64(m["id"])
			reviewID := getInt64(m["review_id"])
			username := resolveUsername(txCtx, m["user_id"])
			body := getString(m["text"])
			updatedAt := getTime(m["date_update"])
			if updatedAt.IsZero() {
				updatedAt = time.Now()
			}

			sqlPreview := fmt.Sprintf("UPDATE review_comments SET review_id=%d, user='%s' WHERE id=%d", reviewID, username, id)
			txCtx.AddMutation(Mutation{
				Table:       "reviewcomment",
				Action:      "UPDATE",
				Description: sqlPreview,
				ApplyPG: func(ctx context.Context, tx *sql.Tx) error {
					query := `
						UPDATE review_comments SET
							review_id = $2,
							user_id = $3,
							body = $4,
							updated_at = $5
						WHERE id = $1;
					`
					_, err := tx.ExecContext(ctx, query, id, reviewID, username, body, updatedAt)
					if err == nil {
						log.Printf("💬 [Replication: ReviewComment UPDATE] ID=%d | ReviewID=%d | User='%s'", id, reviewID, username)
					}
					return err
				},
			})
		}

	case replication.DELETE_ROWS_EVENTv1, replication.DELETE_ROWS_EVENTv2:
		for _, row := range rows {
			m := getRowMap(colNames, row)
			id := getInt64(m["id"])

			sqlPreview := fmt.Sprintf("DELETE FROM review_comments WHERE id=%d", id)
			txCtx.AddMutation(Mutation{
				Table:       "reviewcomment",
				Action:      "DELETE",
				Description: sqlPreview,
				ApplyPG: func(ctx context.Context, tx *sql.Tx) error {
					_, err := tx.ExecContext(ctx, "DELETE FROM review_comments WHERE id = $1;", id)
					if err == nil {
						log.Printf("💬 [Replication: ReviewComment DELETE] ID=%d", id)
					}
					return err
				},
			})
		}
	}
}

func processUserMutations(txCtx *TransactionContext, eventType replication.EventType, colNames []string, rows [][]interface{}) {
	switch eventType {
	case replication.WRITE_ROWS_EVENTv1, replication.WRITE_ROWS_EVENTv2:
		for _, row := range rows {
			m := getRowMap(colNames, row)
			userID := getInt64(m["id"])
			username := getString(m["username"])
			if txCtx != nil && txCtx.LocalUsernames != nil {
				txCtx.LocalUsernames[userID] = username
			}
			txCtx.AddMutation(Mutation{
				Table:       "user",
				Action:      "INSERT",
				Description: fmt.Sprintf("User Map Insert ID=%d -> '%s'", userID, username),
				ApplyMem: func() {
					usernamesByIdMu.Lock()
					usernamesById[userID] = username
					usernamesByIdMu.Unlock()
					log.Printf("👤 [User Map INSERT] Added userID=%d -> username='%s'", userID, username)
				},
			})
		}

	case replication.UPDATE_ROWS_EVENTv1, replication.UPDATE_ROWS_EVENTv2:
		for i := 0; i < len(rows); i += 2 {
			newRow := rows[i+1]
			m := getRowMap(colNames, newRow)
			userID := getInt64(m["id"])
			username := getString(m["username"])
			if txCtx != nil && txCtx.LocalUsernames != nil {
				txCtx.LocalUsernames[userID] = username
			}
			txCtx.AddMutation(Mutation{
				Table:       "user",
				Action:      "UPDATE",
				Description: fmt.Sprintf("User Map Update ID=%d -> '%s'", userID, username),
				ApplyMem: func() {
					usernamesByIdMu.Lock()
					usernamesById[userID] = username
					usernamesByIdMu.Unlock()
					log.Printf("👤 [User Map UPDATE] Updated userID=%d -> username='%s'", userID, username)
				},
			})
		}

	case replication.DELETE_ROWS_EVENTv1, replication.DELETE_ROWS_EVENTv2:
		for _, row := range rows {
			m := getRowMap(colNames, row)
			userID := getInt64(m["id"])
			if txCtx != nil && txCtx.LocalUsernames != nil {
				delete(txCtx.LocalUsernames, userID)
			}
			txCtx.AddMutation(Mutation{
				Table:       "user",
				Action:      "DELETE",
				Description: fmt.Sprintf("User Map Delete ID=%d", userID),
				ApplyMem: func() {
					usernamesByIdMu.Lock()
					delete(usernamesById, userID)
					usernamesByIdMu.Unlock()
					log.Printf("👤 [User Map DELETE] Removed userID=%d", userID)
				},
			})
		}
	}
}

func processCardMutations(txCtx *TransactionContext, eventType replication.EventType, colNames []string, rows [][]interface{}) {
	switch eventType {
	case replication.WRITE_ROWS_EVENTv1, replication.WRITE_ROWS_EVENTv2:
		for _, row := range rows {
			m := getRowMap(colNames, row)
			cardID := getInt64(m["id"])
			code := getString(m["code"])
			if txCtx != nil && txCtx.LocalCardCodes != nil {
				txCtx.LocalCardCodes[cardID] = code
			}
			txCtx.AddMutation(Mutation{
				Table:       "card",
				Action:      "INSERT",
				Description: fmt.Sprintf("Card Code Map Insert ID=%d -> '%s'", cardID, code),
				ApplyMem: func() {
					mysqlCardCodesByIdMu.Lock()
					mysqlCardCodesById[cardID] = code
					mysqlCardCodesByIdMu.Unlock()
					log.Printf("🃏 [Card Code Map INSERT] Added cardID=%d -> code='%s'", cardID, code)
				},
			})
		}

	case replication.UPDATE_ROWS_EVENTv1, replication.UPDATE_ROWS_EVENTv2:
		for i := 0; i < len(rows); i += 2 {
			newRow := rows[i+1]
			m := getRowMap(colNames, newRow)
			cardID := getInt64(m["id"])
			code := getString(m["code"])
			if txCtx != nil && txCtx.LocalCardCodes != nil {
				txCtx.LocalCardCodes[cardID] = code
			}
			txCtx.AddMutation(Mutation{
				Table:       "card",
				Action:      "UPDATE",
				Description: fmt.Sprintf("Card Code Map Update ID=%d -> '%s'", cardID, code),
				ApplyMem: func() {
					mysqlCardCodesByIdMu.Lock()
					mysqlCardCodesById[cardID] = code
					mysqlCardCodesByIdMu.Unlock()
				},
			})
		}

	case replication.DELETE_ROWS_EVENTv1, replication.DELETE_ROWS_EVENTv2:
		for _, row := range rows {
			m := getRowMap(colNames, row)
			cardID := getInt64(m["id"])
			if txCtx != nil && txCtx.LocalCardCodes != nil {
				delete(txCtx.LocalCardCodes, cardID)
			}
			txCtx.AddMutation(Mutation{
				Table:       "card",
				Action:      "DELETE",
				Description: fmt.Sprintf("Card Code Map Delete ID=%d", cardID),
				ApplyMem: func() {
					mysqlCardCodesByIdMu.Lock()
					delete(mysqlCardCodesById, cardID)
					mysqlCardCodesByIdMu.Unlock()
				},
			})
		}
	}
}

func processSideMutations(txCtx *TransactionContext, eventType replication.EventType, colNames []string, rows [][]interface{}) {
	for _, row := range rows {
		m := getRowMap(colNames, row)
		sideID := getInt64(m["id"])
		code := getString(m["code"])
		txCtx.AddMutation(Mutation{
			Table:       "side",
			Action:      formatEventType(eventType),
			Description: fmt.Sprintf("Side Code Map Update ID=%d -> '%s'", sideID, code),
			ApplyMem: func() {
				sideCodesByIdMu.Lock()
				sideCodesById[sideID] = code
				sideCodesByIdMu.Unlock()
			},
		})
	}
}

// ── Helpers ──────────────────────────────────────────────────────────────────

func resolveDeckUUID(txCtx *TransactionContext, val interface{}) string {
	deckIDInt := getInt64(val)
	if deckIDInt != 0 {
		// 1. Check intra-transaction local map first (for newly created decks in the same tx)
		if txCtx != nil && txCtx.LocalDeckUUIDs != nil {
			if u, exists := txCtx.LocalDeckUUIDs[deckIDInt]; exists && u != "" {
				return u
			}
		}

		// 2. Check global preloaded map
		deckUUIDsByIdMu.RLock()
		u, exists := deckUUIDsById[deckIDInt]
		deckUUIDsByIdMu.RUnlock()
		if exists && u != "" {
			return u
		}
	}
	return getString(val)
}

func resolveDecklistUUID(txCtx *TransactionContext, val interface{}) string {
	decklistIDInt := getInt64(val)
	if decklistIDInt != 0 {
		// 1. Check intra-transaction local map first
		if txCtx != nil && txCtx.LocalDecklistUUIDs != nil {
			if u, exists := txCtx.LocalDecklistUUIDs[decklistIDInt]; exists && u != "" {
				return u
			}
		}

		// 2. Check global preloaded map
		decklistUUIDsByIdMu.RLock()
		u, exists := decklistUUIDsById[decklistIDInt]
		decklistUUIDsByIdMu.RUnlock()
		if exists && u != "" {
			return u
		}
	}
	return getString(val)
}

func resolveSideCode(val interface{}) string {
	sideIDInt := getInt64(val)
	if sideIDInt != 0 {
		sideCodesByIdMu.RLock()
		code, exists := sideCodesById[sideIDInt]
		sideCodesByIdMu.RUnlock()
		if exists && code != "" {
			return code
		}
		if sideIDInt == 1 {
			return "corp"
		}
		if sideIDInt == 2 {
			return "runner"
		}
	}
	s := getString(val)
	if s != "" {
		return s
	}
	return "corp"
}

func parseTagsArray(val interface{}) []string {
	str := getString(val)
	if strings.TrimSpace(str) == "" {
		return []string{}
	}
	return strings.Fields(str)
}

func parseFollowsRules(problemVal interface{}) bool {
	s := getString(problemVal)
	return strings.TrimSpace(s) == ""
}

func resolveCardSlug(txCtx *TransactionContext, cardIDVal interface{}) string {
	cardIDInt := getInt64(cardIDVal)
	var code string

	if cardIDInt != 0 {
		// 1. Check intra-transaction local map first
		if txCtx != nil && txCtx.LocalCardCodes != nil {
			code = txCtx.LocalCardCodes[cardIDInt]
		}

		// 2. Check global MySQL card codes map
		if code == "" {
			mysqlCardCodesByIdMu.RLock()
			code = mysqlCardCodesById[cardIDInt]
			mysqlCardCodesByIdMu.RUnlock()
		}
	}

	if code == "" {
		code = getString(cardIDVal)
	}

	cardsByPrintingIdMu.RLock()
	slug, found := cardsByPrintingId[code]
	cardsByPrintingIdMu.RUnlock()

	if found && slug != "" {
		return slug
	}

	if code != "" {
		return code
	}
	return fmt.Sprintf("%v", cardIDVal)
}

func resolveUsername(txCtx *TransactionContext, userIDVal interface{}) string {
	userIDInt := getInt64(userIDVal)
	if userIDInt != 0 {
		// 1. Check intra-transaction local map first
		if txCtx != nil && txCtx.LocalUsernames != nil {
			if username, exists := txCtx.LocalUsernames[userIDInt]; exists && username != "" {
				return username
			}
		}

		// 2. Check global preloaded map
		usernamesByIdMu.RLock()
		username, exists := usernamesById[userIDInt]
		usernamesByIdMu.RUnlock()

		if exists && username != "" {
			return username
		}
	}
	return fmt.Sprintf("user_%d", userIDInt)
}

func getReviewBody(m map[string]interface{}) string {
	if raw, ok := m["rawtext"]; ok {
		s := getString(raw)
		if s != "" {
			return s
		}
	}
	return getString(m["text"])
}

func getRowMap(colNames []string, row []interface{}) map[string]interface{} {
	m := make(map[string]interface{})
	for i, name := range colNames {
		if i < len(row) {
			m[name] = row[i]
		}
	}
	return m
}

func getInt64(v interface{}) int64 {
	if v == nil {
		return 0
	}
	switch val := v.(type) {
	case int:
		return int64(val)
	case int8:
		return int64(val)
	case int16:
		return int64(val)
	case int32:
		return int64(val)
	case int64:
		return val
	case uint:
		return int64(val)
	case uint8:
		return int64(val)
	case uint16:
		return int64(val)
	case uint32:
		return int64(val)
	case uint64:
		return int64(val)
	case string:
		i, _ := strconv.ParseInt(val, 10, 64)
		return i
	case []byte:
		i, _ := strconv.ParseInt(string(val), 10, 64)
		return i
	}
	return 0
}

func getString(v interface{}) string {
	if v == nil {
		return ""
	}
	switch val := v.(type) {
	case string:
		return val
	case []byte:
		return string(val)
	default:
		return fmt.Sprintf("%v", val)
	}
}

func getTime(v interface{}) time.Time {
	if v == nil {
		return time.Time{}
	}
	switch val := v.(type) {
	case time.Time:
		return val
	case string:
		for _, layout := range []string{
			"2006-01-02 15:04:05",
			time.RFC3339,
			"2006-01-02T15:04:05",
		} {
			if t, err := time.Parse(layout, val); err == nil {
				return t
			}
		}
	case []byte:
		return getTime(string(val))
	}
	return time.Time{}
}

func buildGenericChangeSummary(table string, eventType replication.EventType, colNames []string, rows [][]interface{}) string {
	switch eventType {
	case replication.WRITE_ROWS_EVENTv1, replication.WRITE_ROWS_EVENTv2:
		if len(rows) > 0 {
			return buildInsertSQL("", table, colNames, rows[0])
		}
	case replication.UPDATE_ROWS_EVENTv1, replication.UPDATE_ROWS_EVENTv2:
		if len(rows) >= 2 {
			return buildUpdateSQL("", table, colNames, rows[0], rows[1])
		}
	case replication.DELETE_ROWS_EVENTv1, replication.DELETE_ROWS_EVENTv2:
		if len(rows) > 0 {
			return buildDeleteSQL("", table, colNames, rows[0])
		}
	}
	return fmt.Sprintf("%d row(s) affected", len(rows))
}

func formatEventType(et replication.EventType) string {
	switch et {
	case replication.WRITE_ROWS_EVENTv1, replication.WRITE_ROWS_EVENTv2:
		return "INSERT"
	case replication.UPDATE_ROWS_EVENTv1, replication.UPDATE_ROWS_EVENTv2:
		return "UPDATE"
	case replication.DELETE_ROWS_EVENTv1, replication.DELETE_ROWS_EVENTv2:
		return "DELETE"
	default:
		return et.String()
	}
}

func buildInsertSQL(schema, table string, colNames []string, row []interface{}) string {
	var cols []string
	var vals []string
	hasNames := len(colNames) == len(row)

	for i, v := range row {
		if hasNames && colNames[i] != "" {
			cols = append(cols, fmt.Sprintf("`%s`", colNames[i]))
		} else {
			cols = append(cols, fmt.Sprintf("`col_%d`", i+1))
		}
		vals = append(vals, formatSQLValue(v))
	}

	target := fmt.Sprintf("`%s`", table)
	if schema != "" {
		target = fmt.Sprintf("`%s`.`%s`", schema, table)
	}
	return fmt.Sprintf("INSERT INTO %s (%s) VALUES (%s);",
		target, strings.Join(cols, ", "), strings.Join(vals, ", "))
}

func buildUpdateSQL(schema, table string, colNames []string, oldRow, newRow []interface{}) string {
	var setClauses []string
	var whereClauses []string
	hasNames := len(colNames) == len(newRow)

	for i := range newRow {
		col := fmt.Sprintf("`col_%d`", i+1)
		if hasNames && colNames[i] != "" {
			col = fmt.Sprintf("`%s`", colNames[i])
		}

		newVal := formatSQLValue(newRow[i])
		oldVal := formatSQLValue(oldRow[i])

		setClauses = append(setClauses, fmt.Sprintf("%s = %s", col, newVal))

		if oldRow[i] == nil {
			whereClauses = append(whereClauses, fmt.Sprintf("%s IS NULL", col))
		} else {
			whereClauses = append(whereClauses, fmt.Sprintf("%s = %s", col, oldVal))
		}
	}

	target := fmt.Sprintf("`%s`", table)
	if schema != "" {
		target = fmt.Sprintf("`%s`.`%s`", schema, table)
	}
	return fmt.Sprintf("UPDATE %s SET %s WHERE %s;",
		target, strings.Join(setClauses, ", "), strings.Join(whereClauses, " AND "))
}

func buildDeleteSQL(schema, table string, colNames []string, row []interface{}) string {
	var whereClauses []string
	hasNames := len(colNames) == len(row)

	for i, v := range row {
		col := fmt.Sprintf("`col_%d`", i+1)
		if hasNames && colNames[i] != "" {
			col = fmt.Sprintf("`%s`", colNames[i])
		}
		if v == nil {
			whereClauses = append(whereClauses, fmt.Sprintf("%s IS NULL", col))
		} else {
			whereClauses = append(whereClauses, fmt.Sprintf("%s = %s", col, formatSQLValue(v)))
		}
	}

	target := fmt.Sprintf("`%s`", table)
	if schema != "" {
		target = fmt.Sprintf("`%s`.`%s`", schema, table)
	}
	return fmt.Sprintf("DELETE FROM %s WHERE %s;",
		target, strings.Join(whereClauses, " AND "))
}

func getColumnNames(conn *client.Conn, schema, table string) []string {
	key := fmt.Sprintf("%s.%s", schema, table)
	schemaCacheMu.RLock()
	cols, exists := schemaCache[key]
	schemaCacheMu.RUnlock()
	if exists {
		return cols
	}

	if conn == nil {
		return nil
	}

	schemaCacheMu.Lock()
	defer schemaCacheMu.Unlock()

	if cols, exists := schemaCache[key]; exists {
		return cols
	}

	query := fmt.Sprintf("SELECT COLUMN_NAME FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = '%s' AND TABLE_NAME = '%s' ORDER BY ORDINAL_POSITION", schema, table)
	res, err := conn.Execute(query)
	if err != nil || len(res.Values) == 0 {
		return nil
	}

	var names []string
	for i := 0; i < len(res.Values); i++ {
		name, err := res.GetString(i, 0)
		if err == nil {
			names = append(names, name)
		}
	}

	schemaCache[key] = names
	return names
}

func formatSQLValue(v interface{}) string {
	if v == nil {
		return "NULL"
	}
	switch val := v.(type) {
	case string:
		return escapeSQLString(val)
	case []byte:
		return escapeSQLString(string(val))
	case time.Time:
		return fmt.Sprintf("'%s'", val.Format("2006-01-02 15:04:05"))
	case bool:
		if val {
			return "1"
		}
		return "0"
	default:
		return fmt.Sprintf("%v", val)
	}
}

func escapeSQLString(s string) string {
	var b strings.Builder
	b.WriteByte('\'')
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '\'':
			b.WriteString("''")
		case '\\':
			b.WriteString("\\\\")
		case '\x00':
			b.WriteString("\\0")
		case '\n':
			b.WriteString("\\n")
		case '\r':
			b.WriteString("\\r")
		default:
			b.WriteByte(c)
		}
	}
	b.WriteByte('\'')
	return b.String()
}
