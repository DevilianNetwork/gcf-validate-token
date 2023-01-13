<?php

declare(strict_types=1);

namespace Devilian\GcfValidateToken;

use DateTimeImmutable;
use DateTimeZone;
use Lcobucci\JWT\Encoding\CannotDecodeContent;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Token\InvalidTokenStructure;
use Lcobucci\JWT\Token\Parser;
use Lcobucci\JWT\Token\UnsupportedHeaderFound;
use Lcobucci\JWT\UnencryptedToken;

require 'vendor/autoload.php';

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
        $parser = new Parser(new JoseEncoder());

        try {
            $tokenCheck = $parser->parse($this->token);
        } catch (CannotDecodeContent | InvalidTokenStructure | UnsupportedHeaderFound $e) {
            return [
                'error' => $e->getMessage()
            ];
        }
        assert($tokenCheck instanceof UnencryptedToken);

        if ($tokenCheck->claims()->get('iss') !== 'https://securetoken.google.com/' . $this->project) {
            return [
                'error' => 'Invalid iss'
            ];
        }

        if ($tokenCheck->claims()->get('aud')[0] !== $this->project) {
            return [
                'error' => 'Invalid aud'
            ];
        }

        if (time() > $tokenCheck->claims()->get('exp')->getTimestamp()) {
            return [
                'error' => 'Expired token'
            ];
        }

        return [
            "auth_time" => $tokenCheck->claims()->get('auth_time'),
            "user_id" => $tokenCheck->claims()->get('user_id'),
            "email" => $tokenCheck->claims()->get('email'),
            "name" => $tokenCheck->claims()->get('name'),
            "email_verified" => $tokenCheck->claims()->get('email_verified'),
            "iss" => $tokenCheck->claims()->get('iss'),
            "aud" => $tokenCheck->claims()->get('aud'),
            "sub" => $tokenCheck->claims()->get('sub'),
            "iat" => $tokenCheck->claims()->get('iat'),
            "exp" => $tokenCheck->claims()->get('exp'),
            "validation_time" => new DateTimeImmutable("now", new DateTimeZone('+00:00')),
            "token" => $this->token,
            "project" => $this->project
        ];
    }
}
