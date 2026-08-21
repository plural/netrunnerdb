<?php

namespace AppBundle\Entity;

use AppBundle\Behavior\Entity\NormalizableInterface;
use AppBundle\Behavior\Entity\TimestampableInterface;

/**
 * Comment
 */
class Comment implements NormalizableInterface, TimestampableInterface
{
    /**
     * @var integer
     */
    private $id;

    /**
     * @var string
     */
    private $text;

    /**
     * @var \DateTime
     */
    private $dateCreation;

    /**
     * @var boolean
     */
    private $hidden;

    /**
     * @var User
     */
    private $author;

    /**
     * @var Decklist
     */
    private $decklist;

    /**
     * @return int
     */
    public function getId()
    {
        return $this->id;
    }

    /**
     * @return string
     */
    public function getText()
    {
        return $this->text;
    }

    /**
     * @param string $text
     * @return $this
     */
    public function setText(string $text)
    {
        $this->text = $text;

        return $this;
    }

    /**
     * @return \DateTime
     */
    public function getDateCreation()
    {
        return $this->dateCreation;
    }

    /**
     * @param \DateTime $dateCreation
     * @return $this
     */
    public function setDateCreation(\DateTime $dateCreation)
    {
        $this->dateCreation = $dateCreation;

        return $this;
    }

    /**
     * @return bool
     */
    public function getHidden()
    {
        return $this->hidden;
    }

    /**
     * @param bool $hidden
     * @return $this
     */
    public function setHidden(bool $hidden)
    {
        $this->hidden = $hidden;

        return $this;
    }

    /**
     * @return User
     */
    public function getAuthor()
    {
        return $this->author;
    }

    /**
     * @param User $author
     * @return $this
     */
    public function setAuthor(User $author)
    {
        $this->author = $author;

        return $this;
    }

    /**
     * @return Decklist
     */
    public function getDecklist()
    {
        return $this->decklist;
    }

    /**
     * @param Decklist $decklist
     * @return $this
     */
    public function setDecklist(Decklist $decklist)
    {
        $this->decklist = $decklist;

        return $this;
    }

    public function normalize()
    {
        return [
            'id'            => $this->id,
            'text'          => $this->text,
            'hidden'        => $this->hidden,
            'date_creation' => $this->dateCreation->format('c'),
            'user_id'       => $this->author->getId(),
            'user_name'     => $this->author->getUsername(),
            'decklist_id'   => $this->decklist->getId(),
            'decklist_uuid' => $this->decklist->getUuid(),
        ];
    }

    public function getDateUpdate()
    {
        return $this->dateCreation;
    }
}
