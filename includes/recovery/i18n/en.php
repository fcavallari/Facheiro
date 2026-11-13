<?php
////////////////
// English strings for the recovery page. It runs without WordPress, so it
// cannot use the plugin's .po/.mo files: this is a plain Portuguese =>
// English table, loaded by App::pick_language(). Keep the placeholders
// (%s, %d, %1$s...) exactly as in the Portuguese text.
//////////////

// Outside WordPress only recovery.php may load the file.
if (!defined('ABSPATH')) {
    if (!defined('FACHEIRO_RECOVERY_ENTRY')) {
        exit;
    }
}

return array(
    'Modo de recuperação · funciona sem o WordPress'
        => 'Recovery mode · works without WordPress',
    'Recuperação Facheiro'
        => 'Facheiro recovery',
    'Esta página não está usando HTTPS: a chave e os resultados atravessam a rede sem criptografia. Use o endereço https:// se o site tiver um.'
        => 'This page is not using HTTPS: the key and the results cross the network unencrypted. Use the https:// address if the site has one.',
    'Entrar'
        => 'Sign in',
    'Sair'
        => 'Sign out',
    'Digite a chave de recuperação criada em Facheiro > Recuperação, pelo WP-CLI ou no arquivo de chave que você enviou.'
        => 'Enter the recovery key created in Facheiro > Recovery, with WP-CLI, or in the key file you uploaded.',
    'Chave de recuperação'
        => 'Recovery key',
    'Essa chave não é válida.'
        => 'That key is not valid.',
    'Chaves erradas demais. Tente de novo em 15 minutos.'
        => 'Too many wrong keys. Try again in 15 minutes.',
    'Sua sessão expirou. Recarregue a página.'
        => 'Your session expired. Reload the page.',
    'Ação desconhecida.'
        => 'Unknown action.',
    'Esta chave foi adicionada à mão e não expira. Apague %s quando terminar.'
        => 'This key was added by hand and never expires. Delete %s when you are done.',
    'Este site'
        => 'This site',
    'Pasta do WordPress'
        => 'WordPress folder',
    'Versão do WordPress'
        => 'WordPress version',
    'wp-includes/version.php não encontrado'
        => 'wp-includes/version.php not found',
    'não encontrado'
        => 'not found',
    '(lido, nunca executado)'
        => '(read, never run)',
    '%1$s, limite de memória %2$s'
        => '%1$s, memory limit %2$s',
    'Manutenção'
        => 'Maintenance',
    'existe um arquivo .maintenance'
        => '.maintenance exists',
    'uma atualização parou no meio, o que mostra "Momentaneamente indisponível para manutenção programada". Apague o arquivo se nenhuma atualização estiver em andamento.'
        => 'an update stopped halfway, which shows "Briefly unavailable for scheduled maintenance". Delete the file if no update is running.',
    'O que quebrou o site'
        => 'What broke the site',
    'Nenhum log de erros do PHP foi encontrado. Para ter um, adicione %s ao wp-config.php, abra a página quebrada uma vez e depois recarregue esta página.'
        => 'No PHP error log was found. To get one, add %s to wp-config.php, load the broken page once, then reload this page.',
    'Nenhum erro fatal na parte mais recente de: %s.'
        => 'No fatal errors in the latest part of: %s.',
    'Os erros apontam para:'
        => 'The errors point at:',
    '%d erro'
        => '%d error',
    '%d erros'
        => '%d errors',
    'Renomear a pasta desse plugin ou tema (ou o arquivo, no caso de um plugin obrigatório), por exemplo acrescentando %s ao nome por FTP ou pelo gerenciador de arquivos da hospedagem, desativa-o e costuma trazer o site de volta. Depois, faça a varredura abaixo: um código que de repente passa a falhar pode ter sido modificado por malware.'
        => 'Renaming that plugin or theme folder (or a single must-use plugin file), for example by adding %s to its name over FTP or your host\'s file manager, switches it off and usually brings the site back. Then scan below: code that suddenly fails may have been modified by malware.',
    'Erros fatais mais recentes'
        => 'Latest fatal errors',
    'Varredura de malware'
        => 'Scan for malware',
    'A mesma varredura só de relatório da página de administração do Facheiro: arquivos do WordPress, dos plugins e dos temas comparados com as cópias oficiais, malware conhecido, o banco de dados (pelas configurações do wp-config.php), datas de arquivos falsificadas e o crontab do servidor. Nada é alterado.'
        => 'The same report-only scan as the Facheiro admin page: WordPress, plugin and theme files against the official copies, known malware, the database (through the settings in wp-config.php), faked file dates and the server crontab. Nothing is changed.',
    'Logs de acesso (opcional)'
        => 'Access logs (optional)',
    'Iniciar varredura'
        => 'Start scan',
    'Cancelar'
        => 'Cancel',
    'Mantenha esta página aberta enquanto a varredura roda.'
        => 'Keep this page open while the scan runs.',
    'Verificando: '
        => 'Scanning: ',
    'Trabalhando…'
        => 'Working…',
    'Iniciando…'
        => 'Starting…',
    'Erro.'
        => 'Error.',
    'Não foi possível iniciar.'
        => 'Could not start.',
    'Perdemos o contato com o servidor; tentando de novo…'
        => 'Lost contact with the server; retrying…',
    'Não há pasta gravável para o estado da varredura (nem a pasta temporária do sistema nem a wp-content).'
        => 'No writable folder for the scan state (neither the system temp folder nor wp-content).',
    'O caminho dos logs de acesso não existe ou o PHP não consegue lê-lo.'
        => 'The access log path does not exist or PHP cannot read it.',
    'Não foi possível travar o estado da varredura.'
        => 'Could not lock the scan state.',
    'Já há uma varredura em andamento. Cancele-a primeiro.'
        => 'A scan is already running. Cancel it first.',
    'O PHP parou %1$d vezes na mesma parte da etapa "%2$s" (em geral, pelo limite de memória ou de tempo). Aumente o memory_limit ou rode php bin/facheiro.php scanall=1 em um terminal.'
        => 'PHP stopped %1$d times on the same part of the "%2$s" stage (usually the memory or time limit). Raise memory_limit, or run php bin/facheiro.php scanall=1 from a shell.',
    'O estado salvo da varredura não corresponde a este site; inicie uma nova varredura.'
        => 'The saved scan state does not match this site; start a new scan.',
    'Última varredura: %1$s, iniciada em %2$s UTC.'
        => 'Last scan: %1$s, started %2$s UTC.',
    'concluída'
        => 'complete',
    'falhou'
        => 'failed',
    'cancelada'
        => 'cancelled',
    'Exportar JSON'
        => 'Export JSON',
    'Outros %d achados não foram guardados; exporte pela linha de comando para ter a lista completa.'
        => '%d more findings were not kept; export from the command line for the full list.',
    'Nada encontrado.'
        => 'Nothing found.',
    'Os detalhes dos achados ficam em inglês, como nas exportações e na linha de comando.'
        => 'Finding details are in English, as in exports and on the command line.',
    'Gravidade'
        => 'Severity',
    'Tipo'
        => 'Type',
    'Onde'
        => 'Where',
    'Detalhes'
        => 'Details',
    'Contexto'
        => 'Context',
    'Depois da varredura'
        => 'After the scan',
    'Faça um backup dos arquivos e do banco de dados antes de mudar qualquer coisa.'
        => 'Take a backup of the files and the database before changing anything.',
    'Remova o malware conhecido e restaure os arquivos modificados do core, dos plugins e dos temas pela linha de comando: %1$s mostra o mesmo relatório, %2$s simula uma limpeza.'
        => 'Remove known malware and restore modified core, plugin and theme files from the command line: %1$s shows the same report, %2$s previews a cleanup.',
    'Quando o WordPress voltar a carregar, troque todas as senhas e os salts do wp-config.php e revogue esta chave de recuperação.'
        => 'Once WordPress loads again, change every password and the salts in wp-config.php, and revoke this recovery key.',
);
