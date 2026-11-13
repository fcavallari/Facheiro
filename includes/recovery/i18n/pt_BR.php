<?php
////////////////
// Brazilian Portuguese names for the scan stages on the recovery page. The
// page's own text is written in Portuguese; only the stage names come from
// the engine, which stays English (CLI output, exports). Engine label =>
// Portuguese, loaded by App::pick_language().
//////////////

// Outside WordPress only recovery.php may load the file.
if (!defined('ABSPATH')) {
    if (!defined('FACHEIRO_RECOVERY_ENTRY')) {
        exit;
    }
}

return array(
    'Facheiro self-check' => 'Autoverificação do Facheiro',
    'Quick checks' => 'Verificações rápidas',
    'Integrity' => 'Integridade',
    'Timestamps' => 'Datas dos arquivos',
    'Crontab' => 'Crontab',
    'Database' => 'Banco de dados',
    'Access logs' => 'Logs de acesso',
    'Malware signatures (dry run)' => 'Assinaturas de malware (simulação)',
);
