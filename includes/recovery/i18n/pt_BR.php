<?php
////////////////
// Brazilian Portuguese strings for the recovery page. It runs without
// WordPress, so it cannot use the plugin's .po/.mo files: this is a plain
// English => Portuguese table, loaded by App::pick_language(). Keep the
// placeholders (%s, %d, %1$s...) exactly as in the English text.
//////////////

if (!defined('ELDERWARD_RECOVERY_ENTRY')) {
    exit;
}

return array(
    'Recovery mode · works without WordPress'      => 'Modo de recuperação · funciona sem o WordPress',
    'Elderward recovery'                           => 'Recuperação Elderward',
    'This page is not using HTTPS: the key and the results cross the network unencrypted. Use the https:// address if the site has one.' => 'Esta página não está usando HTTPS: a chave e os resultados atravessam a rede sem criptografia. Use o endereço https:// se o site tiver um.',
    'Sign in'                                      => 'Entrar',
    'Sign out'                                     => 'Sair',
    'Enter the recovery key created in Elderward > Recovery, with WP-CLI, or in the key file you uploaded.' => 'Digite a chave de recuperação criada em Elderward > Recuperação, pelo WP-CLI ou no arquivo de chave que você enviou.',
    'Recovery key'                                 => 'Chave de recuperação',
    'That key is not valid.'                       => 'Essa chave não é válida.',
    'Too many wrong keys. Try again in 15 minutes.' => 'Chaves erradas demais. Tente de novo em 15 minutos.',
    'Your session expired. Reload the page.'       => 'Sua sessão expirou. Recarregue a página.',
    'Unknown action.'                              => 'Ação desconhecida.',
    'This key was added by hand and never expires. Delete %s when you are done.' => 'Esta chave foi adicionada à mão e não expira. Apague %s quando terminar.',

    'This site'                                    => 'Este site',
    'WordPress folder'                             => 'Pasta do WordPress',
    'WordPress version'                            => 'Versão do WordPress',
    'wp-includes/version.php not found'            => 'wp-includes/version.php não encontrado',
    'not found'                                    => 'não encontrado',
    '(read, never run)'                            => '(lido, nunca executado)',
    '%1$s, memory limit %2$s'                      => '%1$s, limite de memória %2$s',
    'Maintenance'                                  => 'Manutenção',
    '.maintenance exists'                          => 'existe um arquivo .maintenance',
    'an update stopped halfway, which shows "Briefly unavailable for scheduled maintenance". Delete the file if no update is running.' => 'uma atualização parou no meio, o que mostra "Momentaneamente indisponível para manutenção programada". Apague o arquivo se nenhuma atualização estiver em andamento.',

    'What broke the site'                          => 'O que quebrou o site',
    'No PHP error log was found. To get one, add %s to wp-config.php, load the broken page once, then reload this page.' => 'Nenhum log de erros do PHP foi encontrado. Para ter um, adicione %s ao wp-config.php, abra a página quebrada uma vez e depois recarregue esta página.',
    'No fatal errors in the latest part of: %s.'   => 'Nenhum erro fatal na parte mais recente de: %s.',
    'The errors point at:'                         => 'Os erros apontam para:',
    '%d error'                                     => '%d erro',
    '%d errors'                                    => '%d erros',
    "Renaming that plugin or theme folder (or a single must-use plugin file), for example by adding %s to its name over FTP or your host's file manager, switches it off and usually brings the site back. Then scan below: code that suddenly fails may have been modified by malware." => 'Renomear a pasta desse plugin ou tema (ou o arquivo, no caso de um plugin obrigatório), por exemplo acrescentando %s ao nome por FTP ou pelo gerenciador de arquivos da hospedagem, desativa-o e costuma trazer o site de volta. Depois, faça a varredura abaixo: um código que de repente passa a falhar pode ter sido modificado por malware.',
    'Latest fatal errors'                          => 'Erros fatais mais recentes',

    'Scan for malware'                             => 'Varredura de malware',
    'The same report-only scan as the Elderward admin page: WordPress, plugin and theme files against the official copies, known malware, the database (through the settings in wp-config.php), faked file dates and the server crontab. Nothing is changed.' => 'A mesma varredura só de relatório da página de administração do Elderward: arquivos do WordPress, dos plugins e dos temas comparados com as cópias oficiais, malware conhecido, o banco de dados (pelas configurações do wp-config.php), datas de arquivos falsificadas e o crontab do servidor. Nada é alterado.',
    'Access logs (optional)'                       => 'Logs de acesso (opcional)',
    'Start scan'                                   => 'Iniciar varredura',
    'Cancel'                                       => 'Cancelar',
    'Keep this page open while the scan runs.'     => 'Mantenha esta página aberta enquanto a varredura roda.',
    'Scanning: '                                   => 'Verificando: ',
    'Working…'                                     => 'Trabalhando…',
    'Starting…'                                    => 'Iniciando…',
    'Error.'                                       => 'Erro.',
    'Could not start.'                             => 'Não foi possível iniciar.',
    'Lost contact with the server; retrying…'      => 'Perdemos o contato com o servidor; tentando de novo…',
    'No writable folder for the scan state (neither the system temp folder nor wp-content).' => 'Não há pasta gravável para o estado da varredura (nem a pasta temporária do sistema nem a wp-content).',
    'The access log path does not exist or PHP cannot read it.' => 'O caminho dos logs de acesso não existe ou o PHP não consegue lê-lo.',
    'Could not lock the scan state.'               => 'Não foi possível travar o estado da varredura.',
    'A scan is already running. Cancel it first.'  => 'Já há uma varredura em andamento. Cancele-a primeiro.',
    'PHP stopped %1$d times on the same part of the "%2$s" stage (usually the memory or time limit). Raise memory_limit, or run php bin/elderward.php scanall=1 from a shell.' => 'O PHP parou %1$d vezes na mesma parte da etapa "%2$s" (em geral, pelo limite de memória ou de tempo). Aumente o memory_limit ou rode php bin/elderward.php scanall=1 em um terminal.',
    'The saved scan state does not match this site; start a new scan.' => 'O estado salvo da varredura não corresponde a este site; inicie uma nova varredura.',

    'Quick checks'                                 => 'Verificações rápidas',
    'Integrity'                                    => 'Integridade',
    'Timestamps'                                   => 'Datas dos arquivos',
    'Crontab'                                      => 'Crontab',
    'Database'                                     => 'Banco de dados',
    'Access logs'                                  => 'Logs de acesso',
    'Malware signatures (dry run)'                 => 'Assinaturas de malware (simulação)',

    'Last scan: %1$s, started %2$s UTC.'           => 'Última varredura: %1$s, iniciada em %2$s UTC.',
    'complete'                                     => 'concluída',
    'failed'                                       => 'falhou',
    'cancelled'                                    => 'cancelada',
    'Export JSON'                                  => 'Exportar JSON',
    '%d more findings were not kept; export from the command line for the full list.' => 'Outros %d achados não foram guardados; exporte pela linha de comando para ter a lista completa.',
    'Nothing found.'                               => 'Nada encontrado.',
    'Finding details are in English, as in exports and on the command line.' => 'Os detalhes dos achados ficam em inglês, como nas exportações e na linha de comando.',
    'Severity'                                     => 'Gravidade',
    'Type'                                         => 'Tipo',
    'Where'                                        => 'Onde',
    'Details'                                      => 'Detalhes',
    'Context'                                      => 'Contexto',

    'After the scan'                               => 'Depois da varredura',
    'Take a backup of the files and the database before changing anything.' => 'Faça um backup dos arquivos e do banco de dados antes de mudar qualquer coisa.',
    'Remove known malware and restore modified core, plugin and theme files from the command line: %1$s shows the same report, %2$s previews a cleanup.' => 'Remova o malware conhecido e restaure os arquivos modificados do core, dos plugins e dos temas pela linha de comando: %1$s mostra o mesmo relatório, %2$s simula uma limpeza.',
    'Once WordPress loads again, change every password and the salts in wp-config.php, and revoke this recovery key.' => 'Quando o WordPress voltar a carregar, troque todas as senhas e os salts do wp-config.php e revogue esta chave de recuperação.',
);
