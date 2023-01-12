<?php

namespace Devilian\GcfValidateToken;

use PHPUnit\Framework\TestCase;

final class GcfValidateTokenTest extends TestCase
{
    public function testClassConstructor()
    {
        $auth = new GcfValidateToken('123', 'private');

        $this->assertSame('123', $auth->token);
        $this->assertSame('private', $auth->project);
        // $this->assertEmpty($auth->anything);
    }
}
