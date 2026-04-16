<?php

namespace Febryntara\LaravelBotGuardian\Tests;

use Febryntara\LaravelBotGuardian\RecidivistBlocker;
use Illuminate\Support\Facades\Cache;

class RecidivistBlockerTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        config(['botguardian.recidivist.enabled' => true]);
        config(['botguardian.recidivist.max_blocks_before_permanent' => 3]);
        config(['botguardian.recidivist.count_window' => 86400]);
    }

    public function test_returns_false_until_threshold()
    {
        $blocker = new RecidivistBlocker();
        $ip = '10.0.0.55';

        // Record 2 blocks — should not be permanent yet
        $blocker->recordBlock($ip);
        $blocker->recordBlock($ip);
        $this->assertFalse($blocker->shouldPermanentBlock($ip));
        $this->assertEquals(2, $blocker->getBlockCount($ip));
    }

    public function test_returns_true_when_threshold_reached()
    {
        $blocker = new RecidivistBlocker();
        $ip = '10.0.0.56';

        // Record 3 blocks — threshold reached
        $blocker->recordBlock($ip);
        $blocker->recordBlock($ip);
        $blocker->recordBlock($ip);
        $this->assertTrue($blocker->shouldPermanentBlock($ip));
        $this->assertEquals(3, $blocker->getBlockCount($ip));
    }

    public function test_reset_clears_block_count()
    {
        $blocker = new RecidivistBlocker();
        $ip = '10.0.0.57';
        $blocker->recordBlock($ip);
        $blocker->recordBlock($ip);
        $this->assertEquals(2, $blocker->getBlockCount($ip));
        $blocker->resetBlockCount($ip);
        $this->assertEquals(0, $blocker->getBlockCount($ip));
    }

    public function test_returns_false_when_disabled()
    {
        config(['botguardian.recidivist.enabled' => false]);
        $blocker = new RecidivistBlocker();
        $ip = '10.0.0.58';
        $blocker->recordBlock($ip);
        $blocker->recordBlock($ip);
        $blocker->recordBlock($ip);
        $this->assertFalse($blocker->shouldPermanentBlock($ip));
    }
}
