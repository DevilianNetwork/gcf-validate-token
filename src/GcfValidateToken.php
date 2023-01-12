<?php

namespace Devilian\GcfValidateToken;

class GcfValidateToken
{
    public ?string $token;
    public ?string $project;

    public function __construct(string $token, ?string $project)
    {
        $this->token = $token;
        $this->project = $project;
    }

    public function validate()
    {
        return $this->token . " " . $this->project;
    }
}
