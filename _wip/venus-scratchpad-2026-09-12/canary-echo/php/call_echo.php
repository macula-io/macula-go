<?php

declare(strict_types=1);

/**
 * Canary caller for io.macula.echo using macula-php v0.3.4-1-gea85395: the shape of
 * examples/02_call.php, pointed at the echo service. Prepared for the
 * hecate-echo on macula 10.24.0 canary; run only when Saturnus calls the
 * baseline. One fresh identity, one call, no loops.
 *
 * Match rule (Saturnus): "match" ignores text versus bytes (and map key
 * order, not applicable here). macula-php can see text versus bytes
 * (Value->kind, src/Value.php:27), so "exact_match" also requires the reply
 * to be text. macula-php has no map payload type (src/Value.php:10,
 * cabi/value.go:12), so the map call is recorded as skipped.
 *
 * Usage: MACULA_CANARY_RUN=<run id> MACULA_LIBRARY_PATH=<libmacula.so> php call_echo.php <station-host> [port]
 */

require '/home/rl/work/github.com/macula-io/macula-php/vendor/autoload.php';

use Macula\KeyPair;
use Macula\Session;
use Macula\Value;

const PROCEDURE = 'io.macula.echo';
const SDK = 'macula-php';
const SDK_VERSION = 'v0.3.4-1-gea85395';

$host = $argv[1] ?? null;
$port = (int) ($argv[2] ?? 4433);
if ($host === null) {
    fwrite(STDERR, "usage: php call_echo.php <station-host> [port]\n");
    exit(2);
}
$station = "{$host}:{$port}";

function utc(): string
{
    return (new DateTimeImmutable('now', new DateTimeZone('UTC')))->format('Y-m-d\TH:i:s.u\Z');
}

function emit(string $station, array $fields): void
{
    echo json_encode(['sdk' => SDK, 'sdk_version' => SDK_VERSION, 'run' => (defined('RUN') ? RUN : null), 'station' => $station] + $fields, JSON_UNESCAPED_SLASHES), "\n";
}

/** @return array{match: bool, exact_match: bool, reply_kind: string, reply: ?string} */
function judgeText(Value $v, string $expected): array
{
    $isText = $v->kind === Value::KIND_TEXT;
    $isBytes = $v->kind === Value::KIND_BYTES;
    $kind = $isText ? 'text' : ($isBytes ? 'bytes' : "kind-{$v->kind}");
    $content = ($isText || $isBytes) && $v->bytesValue === $expected;
    return [
        'match' => $content,
        'exact_match' => $isText && $v->bytesValue === $expected,
        'reply_kind' => $kind,
        'reply' => ($isText || $isBytes) ? $v->bytesValue : null,
    ];
}

if (($argv[1] ?? '') === '--self-check') {
    $cases = [
        ['text hello', Value::text('hello'), true, true],
        ['bytes hello', Value::bytes('hello'), true, false],
        ['text other', Value::text('hullo'), false, false],
        ['int', Value::int(5), false, false],
    ];
    $bad = 0;
    foreach ($cases as [$name, $value, $wantContent, $wantExact]) {
        $j = judgeText($value, 'hello');
        $pass = $j['match'] === $wantContent && $j['exact_match'] === $wantExact;
        $bad += $pass ? 0 : 1;
        printf("  %s %s: match=%s exact_match=%s\n", $pass ? 'ok  ' : 'FAIL', $name, var_export($j['match'], true), var_export($j['exact_match'], true));
    }
    exit($bad === 0 ? 0 : 1);
}

$run = getenv('MACULA_CANARY_RUN');
if ($run === false || $run === '') {
    fwrite(STDERR, "MACULA_CANARY_RUN (the run id Saturnus names) is required\n");
    exit(2);
}
define('RUN', $run);

$ok = true;
$identity = KeyPair::generate();
$connectStart = hrtime(true);
try {
    $session = Session::connect($host, $port, $identity);
} catch (Throwable $e) {
    emit($station, ['utc' => utc(), 'call' => 'connect', 'match' => false, 'exact_match' => false,
        'duration_ms' => intdiv(hrtime(true) - $connectStart, 1_000_000), 'error' => $e->getMessage()]);
    exit(1);
}

$realm = str_repeat("\x00", 32); // the all-zero realm
$when = utc();
$t0 = hrtime(true);
try {
    $response = $session->call(PROCEDURE, $realm, Value::text('hello'), timeoutMs: 5000);
    $ms = intdiv(hrtime(true) - $t0, 1_000_000);
    if ($response->isError()) {
        emit($station, ['utc' => $when, 'call' => 'hello', 'match' => false, 'exact_match' => false,
            'duration_ms' => $ms, 'is_error' => true, 'code' => $response->code(), 'name' => $response->name(),
            'detail' => $response->detail(), 'reported_by' => bin2hex($response->reportedBy())]);
        $ok = false;
    } else {
        $j = judgeText($response->payload(), 'hello');
        emit($station, ['utc' => $when, 'call' => 'hello'] + $j + ['duration_ms' => $ms, 'is_error' => false,
            'responded_by' => bin2hex($response->respondedBy())]);
        $ok = $ok && $j['match'];
    }
} catch (Throwable $e) {
    emit($station, ['utc' => $when, 'call' => 'hello', 'match' => false, 'exact_match' => false,
        'duration_ms' => intdiv(hrtime(true) - $t0, 1_000_000), 'error' => $e->getMessage()]);
    $ok = false;
}

emit($station, ['utc' => utc(), 'call' => 'map',
    'skipped' => 'macula-php has no map payload type (src/Value.php:10, cabi/value.go:12)']);

$session->close();
exit($ok ? 0 : 1);
