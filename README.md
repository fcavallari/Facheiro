<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/img/facheiro-logo.svg">
    <img src="assets/img/facheiro-logo-on-light.svg" alt="Facheiro" width="400">
  </picture>
</p>

<p align="center"><a href="README.en.md">Read in English</a></p>

O Facheiro é um conjunto gratuito de ferramentas de varredura de malware e resposta a incidentes para sites WordPress. Ele examina os arquivos em busca de sinais de invasão e consegue remover malware conhecido, compara o core, os plugins e os temas com os pacotes oficiais do wordpress.org, varre o banco de dados atrás de administradores indevidos e conteúdo injetado, e lê os logs de acesso em busca de indicadores de comprometimento (IoCs) conhecidos, para que você entenda como o ataque aconteceu, e não apenas limpe o que ele deixou.

O que ele oferece:

- **Uma varredura de tudo, só de relatório**, pelo menu **Facheiro** do painel, em segundo plano pelo WP-Cron ou agendada, com os achados do mais grave ao mais leve, marcas de falso positivo presas ao arquivo revisado, download de amostras criptografadas e exportação em NDJSON.
- **Assinaturas personalizadas** escritas e testadas no painel (só detectam), compartilhadas em JSON com a linha de comando.
- **Blindagem do servidor** para Apache/LiteSpeed (`.htaccess`, aplicado com verificação de saúde e reversão automática) e Nginx (um arquivo de configuração para incluir), a partir do modelo Recomendado ou Rigoroso ou proteção por proteção, e uma verificação ao vivo do que o servidor de fato bloqueia.
- **Modo de recuperação**: uma página protegida por chave que funciona quando o próprio WordPress não carrega (tela branca, erro crítico), mostra o que quebrou o site e roda a varredura completa.
- **Ferramentas para assistentes de IA** por MCP (WordPress 6.9+ com o plugin MCP Adapter), para que Claude, ChatGPT, Antigravity ou Cursor rodem varreduras, expliquem os achados e escrevam assinaturas com você, sem nunca limpar nem alterar arquivos.
- **Limpeza e restauração** pelo WP-CLI ou pela CLI independente, sempre com uma simulação antes.
- **Português do Brasil e inglês** no painel e na página de recuperação: o plugin é escrito em português e traz a tradução para o inglês.

Ele roda de quatro maneiras, todas sobre o mesmo motor:

- **Plugin do WordPress**: as páginas do painel descritas acima.
- **WP-CLI**: `wp facheiro ...` roda todos os scanners e os comandos de limpeza, restauração e blindagem, com saída em texto ou NDJSON e códigos de saída próprios para alertas.
- **Modo de recuperação**: `recovery.php` na pasta do plugin, para quando o WordPress não carrega mais mas o servidor web ainda executa PHP.
- **CLI independente**: `php bin/facheiro.php ...` não precisa de nenhum WordPress funcionando: envie a pasta para um site fora do ar e faça a varredura pelo shell.

Nada sai do servidor por conta própria. As únicas requisições externas vão para o wordpress.org durante a verificação de integridade (manifestos de checksums e pacotes oficiais); as verificações de blindagem só fazem requisições ao próprio site.

Ele nasceu como uma variação do Jetpack Cleanup Util, empacotada para que qualquer pessoa rode no próprio servidor. O nome vem do facheiro, um cacto da caatinga: na seca, o sertanejo queima os espinhos dele, e o que sobra é água e alimento.

A página do projeto, [facheiro.space.fast](https://facheiro.space.fast/) (em português, com o inglês em `/en/`), fica em `site/`.

## Requisitos

- WordPress 6.0+ e PHP 7.2+ para o plugin; a CLI independente e o modo de recuperação rodam em PHP 5.6+
- Acesso ao shell (WP-CLI ou `php`) para limpar ou restaurar arquivos; as páginas do painel não precisam de shell
- WordPress 6.9+ e o plugin [MCP Adapter](https://github.com/WordPress/mcp-adapter) para as ferramentas de assistentes de IA
- Apache ou LiteSpeed com `AllowOverride` para as regras de blindagem que o próprio Facheiro grava; no Nginx, você inclui o arquivo gerado na configuração do servidor

A varredura por assinaturas, as verificações rápidas e as de datas não precisam de mais nada. Os outros scanners usam extensões PHP que servidores mais fechados às vezes não têm; a falta de uma delas aparece como um achado `ERROR`, em vez de a verificação ser pulada:

| Necessário para | Requisito |
|---|---|
| Logs rotacionados em `.gz` | extensão zlib |
| Verificação de integridade online (CLI independente) | extensão curl, ou `allow_url_fopen=On` (o plugin usa a API HTTP do WordPress) |
| Verificação de temas e qualquer restauração | extensão zip |
| Varredura do banco de dados (CLI independente) | extensão mysqli (o plugin usa a conexão do WordPress) |
| Varredura do crontab | `shell_exec` fora de `disable_functions` |

## O plugin

O Facheiro ainda não está no WordPress.org. Instale a partir deste repositório; a pasta precisa se chamar `facheiro`:

```
cd wp-content/plugins
git clone https://github.com/fcavallari/Facheiro.git facheiro
wp plugin activate facheiro
```

(ou baixe o repositório como zip, descompacte em `wp-content/plugins/facheiro/` e ative na tela de Plugins). A ativação cria uma tabela, `{prefix}facheiro_findings`. Depois:

1. **Facheiro (menu do painel) → Iniciar varredura.** A varredura roda em segundo plano pelo WP-Cron, então você pode fechar a aba e voltar depois; ela não altera nada no site. Os achados aparecem do mais grave ao mais leve, com filtros por gravidade, e podem ser exportados em texto ou NDJSON. A aba **Configurações** define o arquivo ou a pasta de logs de acesso que toda varredura examina, permite rodar as varreduras só enquanto a página estiver aberta (para servidores em que o WP-Cron não é confiável) e agenda varreduras automáticas diárias, duas vezes por dia ou semanais. Cada configuração tem um **?** com mais detalhes, e a aba **Ajuda** da tela explica a página inteira.
2. **Revise os achados.** *Marcar como falso positivo* registra, com uma nota, um achado revisado e inofensivo: as varreduras seguintes o mantêm no registro (e na exportação JSON, com `"false_positive": true`), mas fora das contagens e da visão padrão. A marca num arquivo guarda o SHA-256 dele e deixa de valer assim que o arquivo muda, então o achado volta. A marca num achado do banco de dados (uma opção, um post, `siteurl`/`home`, definições de papéis) faz o mesmo com o SHA-256 do valor que a varredura leu, então uma carga trocada dentro de uma opção já liberada volta a aparecer, mesmo que a mesma assinatura continue batendo. Marcas de banco de dados salvas antes de os valores passarem a ter hash voltam uma vez; marque de novo. *Baixar amostra* empacota um arquivo apontado num zip criptografado com a senha `infected` (AES-256), com um `manifest.json`, para você enviar a um analista ou a uma sandbox; o Facheiro nunca envia nada, e nunca empacota o `wp-config.php` nem arquivos de fora da raiz do WordPress. Achados de arquivo também mostram o SHA-256 com um link de consulta ao VirusTotal (só o hash, aberto pelo seu navegador).
3. **Aba Assinaturas.** Adicione assinaturas personalizadas para arquivos, valores de opções ou conteúdo de posts, teste contra uma amostra colada ou um arquivo do site e importe/exporte em JSON (veja [Assinaturas personalizadas](#assinaturas-personalizadas)). Assinaturas personalizadas só detectam.
4. **Aba Blindagem.** Regras de servidor que recusam o que nunca deveria ser servido (veja [Blindagem](#blindagem)).
5. **Aba Recuperação.** Uma chave para o modo de recuperação, a página que faz a varredura do site quando o WordPress não carrega mais (veja [Modo de recuperação](#modo-de-recuperação)).
6. **Aja sobre os resultados pelo WP-CLI**, depois de fazer um backup:

```
wp facheiro scan --dryrun                        # simula a limpeza por assinaturas
wp facheiro scan                                 # remove malware conhecido dos arquivos infectados
wp facheiro scan --allfiles                      # ... examinando todos os arquivos, não só as extensões de risco
wp facheiro integrity --restore --dryrun         # simula a restauração de arquivos alterados/ausentes do core, plugins e temas
wp facheiro integrity --restore --quarantine-dir=/path/outside/webroot
```

Cada scanner também é um comando do WP-CLI, com `--format=json` para NDJSON e os códigos de saída descritos mais abaixo:

```
wp facheiro scanall [--log=/var/log/apache2] [--format=json]   # todos os scanners, só relatório
wp facheiro quick                                # PHP em uploads, ganchos prepend, mu-plugins, PHP oculto
wp facheiro integrity [--checksum-dir=/path] [--locale=pt_BR]
wp facheiro times                                # relatório de anomalias de datas
wp facheiro db                                   # varredura do banco de dados, só leitura
wp facheiro cron                                 # crontab do usuário atual
wp facheiro log /var/log/apache2 [--correlate] [--window=300]
```

```
wp facheiro harden [--server=apache|nginx] [--preset=recommended|strict] [--features=a,b] [--print|--apply [--unverified]|--remove|--check]
wp facheiro recovery-key create|status|revoke [--expires=<days>|never]
```

`wp help facheiro <comando>` lista as opções de cada comando. Em multisite o menu fica no painel da rede e é restrito a super administradores. A saída da linha de comando e os detalhes dos achados ficam em inglês, em qualquer idioma do site.

### Blindagem

A aba Blindagem (e o `wp facheiro harden`) grava regras de servidor a partir de um modelo (**Recomendado** ou **Rigoroso**) ou de qualquer combinação de proteções:

| Proteção | Modelo | Apache/LiteSpeed (`.htaccess`) | Nginx |
|---|---|---|---|
| Bloquear PHP em uploads | Recomendado | `uploads/.htaccess` com `FilesMatch` negado | `location ~* ^/wp-content/uploads/.*\.php` negado |
| Bloquear arquivos internos do WordPress | Recomendado | `wp-includes/.htaccess` (libera `wp-tinymce.php`, `ms-files.php`), `wp-admin/includes/.htaccess` | location por regex com as mesmas exceções, `^~ /wp-admin/includes/` |
| Proteger arquivos wp-config | Recomendado | `^wp-config` (também cópias `.bak`, `.old`) | `^/wp-config` |
| Bloquear backups, logs e configurações do servidor | Recomendado | `.bak .old .orig .save .swp .sql .log .ini .sh ~`, `readme.html`, `license.txt` | igual |
| Bloquear arquivos e pastas ocultos | Recomendado | arquivos com ponto e uma regra de rewrite para pastas com ponto, `.well-known` liberado | `location ~ /\.(?!well-known)` |
| Desligar a listagem de pastas | Recomendado | `Options -Indexes` | `autoindex off` |
| Bloquear PHP direto em temas | Rigoroso | `themes/.htaccess` | location por regex |
| Cabeçalhos de segurança | Rigoroso | `nosniff`, `X-Frame-Options SAMEORIGIN`, `Referrer-Policy` | `add_header ... always` |
| Desligar o XML-RPC | Rigoroso | `xmlrpc.php` negado | `location = /xmlrpc.php` |
| Bloquear PHP direto em plugins | só personalizado | regra de rewrite, `facheiro/recovery.php` liberado | location por regex, mesma exceção |

No Apache/LiteSpeed as regras ficam entre `# BEGIN Facheiro` e `# END Facheiro` (`insert_with_markers()`). Antes de gravar, todos os arquivos necessários precisam ter permissão de escrita e o site precisa conseguir acessar a si mesmo por HTTP: a página inicial, o login, o admin-ajax e um endereço dentro de cada outra pasta que vai receber regras (uma folha de estilo em `wp-includes`, o `style.css` do tema ativo…) são requisitados antes e depois, e se algum deles começar a falhar (um 5xx porque `Options` não é permitido pelo `AllowOverride`, falta de resposta, ou uma página que era servida e passou a ser recusada) todos os arquivos são restaurados byte a byte. Uma regra que o servidor rejeita responde 500 a toda requisição, inclusive as do painel; por isso, quando o site não consegue acessar a si mesmo (requisições de loopback bloqueadas pela hospedagem), nada é gravado, a menos que você marque **Aplicar sem a verificação de segurança** (`--unverified`); remover regras nunca precisa disso. A remoção retira os blocos e apaga os arquivos que o Facheiro criou. A configuração do Nginx é baixada (ou impressa com `--print`) e incluída no bloco `server { }`, acima da location do PHP. **Verificar agora** / `--check` requisita arquivos que não existem (um PHP em uploads, um dump `.sql`, uma pasta com ponto…) e só dá uma proteção como ativa quando o servidor os recusa; assim ele confere também regras feitas à mão e não cria nada.

### Modo de recuperação

`wp-content/plugins/facheiro/recovery.php` faz a varredura do site **sem carregar o WordPress**, para quando um erro fatal ou um malware derruba o site (e o painel junto). Ele mostra os erros fatais de PHP mais recentes dos logs, com o plugin ou tema para o qual apontam, a versão do WordPress e o estado do `.maintenance`, e roda a mesma varredura só de relatório do painel, banco de dados incluído (credenciais lidas do `wp-config.php`, que nunca é executado), avançando em requisições curtas.

Ele fica inerte enquanto não existir uma chave: sem `wp-content/facheiro-recovery-key.php` (ou com uma chave expirada) responde 404. Crie a chave na aba Recuperação ou com `wp facheiro recovery-key create --expires=7`; o Facheiro guarda apenas o SHA-256 dela. Se o site já estiver quebrado, crie o arquivo à mão:

```
<?php exit; ?>
{"key":"pelo-menos-24-caracteres-aleatorios-seus"}
```

O login define um cookie assinado por HMAC, HttpOnly e SameSite=Strict, válido por uma hora e preso à chave (trocar ou revogar a chave encerra todas as sessões); as ações levam um token preso à sessão; uma chave gerada errada é simplesmente recusada (com cerca de 190 bits, um atraso não acrescenta nada e só deixaria qualquer pessoa ocupar os processos do PHP), e para chaves escritas à mão cada tentativa errada custa um segundo, com bloqueio do cliente por 15 minutos depois de 10 tentativas erradas (atrás de um proxy, vale o endereço do cliente encaminhado; no máximo 500 clientes são acompanhados). Chaves geradas nunca bloqueiam ninguém, então um invasor não consegue trancar o dono do lado de fora. A pasta de estado precisa pertencer ao usuário do PHP e estar fechada para todos os outros (uma pasta compartilhada em `/tmp` criada por outra conta é ignorada), e cada passo reconstrói as opções da varredura, de modo que um arquivo de estado adulterado não consegue transformar a varredura em limpeza. A página guarda o estado em arquivos protegidos por `exit` na pasta temporária do sistema (ou em `wp-content/facheiro-recovery/`). Revogue a chave quando terminar.

### Detecção de adulteração

Um malware que executa PHP no site tem os mesmos direitos que o Facheiro, então nenhum plugin consegue impedi-lo de alterar o Facheiro. O que o Facheiro faz é tornar a alteração visível, de duas maneiras, e relatar as duas em toda varredura (painel, WP-Cron, WP-CLI, assistentes e página de recuperação):

- **Autoverificação.** Todas as outras verificações pulam a pasta do próprio Facheiro (as assinaturas dele bateriam nelas mesmas), então a varredura começa pela etapa *Autoverificação do Facheiro*: cada arquivo do plugin é comparado com os checksums do wordpress.org para esta versão ou, quando o wordpress.org não tem nenhum (ou está inacessível), com o `checksums.json` que acompanha o plugin. Arquivos PHP alterados ou acrescentados são HIGH, e as páginas do painel passam a avisar que os resultados podem não ser confiáveis (até a varredura sair limpa ou você marcar esses achados como falsos positivos). Nada na pasta é pulado: num checkout do git os arquivos de desenvolvimento (testes, ferramentas de build) são conferidos pela mesma lista, um arquivo PHP dentro de `.git` é relatado, e uma pasta `vendor/` ou `node_modules/` é relatada como não verificada, já que nenhuma lista cobre dependências instaladas. A lista que acompanha o plugin pega injetores em massa e arquivos plantados, mas um invasor capaz de gravar arquivos também consegue reescrevê-la; só a referência do wordpress.org (ou um download novo, rodado como CLI independente) cobre esse caso. `selfcheck=1` / `wp facheiro selfcheck` roda só essa etapa; `noselfcheck=1` a pula.
- **Configurações seladas.** Os falsos positivos salvos, as assinaturas personalizadas e as configurações de varredura ficam no banco de dados, onde uma injeção de SQL sozinha poderia acrescentar um falso positivo para um backdoor ou apagar a assinatura que o pega. Toda alteração feita pelo Facheiro também grava o SHA-256 de cada entrada em `wp-content/facheiro-seal.php` (protegido como o arquivo da chave de recuperação), que um invasor com acesso apenas ao banco não consegue reescrever. Um falso positivo que não confere com o selo é ignorado, então o achado dele volta (`TAMPER_FALSE_POSITIVE`); assinaturas personalizadas e configurações alteradas por fora do Facheiro são relatadas (`TAMPER_SIGNATURE`, `TAMPER_SETTINGS`), e um selo apagado ou corrompido é recriado e relatado (`TAMPER_SEAL_MISSING`). As páginas do painel listam cada alteração com **Manter** (depois de revisar) ou **Remover**; `wp facheiro seal status` e `wp facheiro seal accept [--collection=<nome>]` fazem o mesmo pela linha de comando. Depois de restaurar o banco a partir de um backup, ou de mover o site sem o arquivo do selo, revise e aceite.

Isso é detecção, não prevenção: um invasor capaz de gravar arquivos consegue reescrever também o selo e a lista de checksums que acompanha o plugin.

### Assistentes de IA (MCP)

No WordPress 6.9+ o Facheiro registra abilities do WordPress (categoria `facheiro`) que o plugin oficial [MCP Adapter](https://github.com/WordPress/mcp-adapter) expõe a qualquer cliente MCP: Claude Desktop e Claude Code, Antigravity, Cursor e ChatGPT, onde houver conectores MCP personalizados. A aba **Assistentes de IA** mostra a configuração do cliente para o site, por STDIO via WP-CLI (`wp mcp-adapter serve --user=<admin>`) ou por HTTP via `@automattic/mcp-wordpress-remote` com uma senha de aplicativo.

| Ability | O que faz |
|---|---|
| `facheiro/get-status`, `start-scan`, `advance-scan`, `cancel-scan` | Rodam uma varredura em segundo plano, só de relatório, e a acompanham; `advance-scan` a faz avançar pela própria requisição quando o WP-Cron está parado |
| `facheiro/list-findings`, `get-finding`, `read-flagged-file` | Leem os resultados e os primeiros 64 KB de um arquivo apontado (dentro da raiz, nunca o `wp-config.php`) |
| `facheiro/mark-false-positive`, `unmark-false-positive`, `list-false-positives` | Decisões de revisão, com nota obrigatória |
| `facheiro/list-signatures`, `test-signature`, `save-signature`, `delete-signature` | Rascunham, comprovam e salvam assinaturas que só detectam |
| `facheiro/triage` (prompt MCP) | Uma investigação guiada: veredito, evidências e um plano de limpeza que o usuário executa |

Só administradores (`Facheiro_Plugin::can_manage()`) podem chamá-las. Não existe ability que limpe, restaure ou grave arquivos do site. Toda saída que carrega dados escaneados traz um `untrusted_data_notice`, e o prompt de triagem orienta o assistente a tratar nomes de arquivo, caminhos, detalhes e conteúdo de arquivos como dados controlados pelo invasor, nunca como instruções. Sem MCP, a aba oferece um resumo (instruções mais os 100 principais achados em linhas JSON, entre marcadores de dado não confiável) para colar em qualquer chatbot. `tests/mcp-stdio.js` conduz uma sessão inteira por STDIO.

O plugin guarda o relatório mais recente em uma tabela (`{prefix}facheiro_findings`) e o estado da varredura em uma opção; a desinstalação remove as duas, a pasta de trabalho em `wp-content/uploads/facheiro/`, os blocos do Facheiro nos `.htaccess`, a chave e o estado de recuperação e o selo de adulteração.

## A CLI independente

Para um site que não carrega mais, ou um servidor sem WP-CLI, rode os mesmos scanners direto da pasta do plugin. As opções são argumentos `chave=valor`:

Mantenha o Facheiro numa pasta só dele: a pasta do plugin, ou qualquer pasta que contenha apenas o `bin/` e o `includes/` dele. A própria pasta nunca é escaneada (as assinaturas do código-fonte bateriam nelas mesmas), então um diretório de varredura que seja essa pasta, ou esteja dentro dela, é recusado com um erro, em vez de ser dado como limpo. Enviar `bin/` e `includes/` direto para a pasta home, acima de `public_html`, é o jeito mais comum de cair nisso.

```
php bin/facheiro.php scanall=1 scandirectory=/path/to/wp-root         # todos os scanners, só relatório
php bin/facheiro.php scanall=1 scanlog=/var/log/apache2 scandirectory=/path/to/wp-root  # ... com os logs
php bin/facheiro.php scanall=1 format=json scandirectory=/path/to/wp-root               # legível por máquina
```

`scanall=1` roda as verificações rápidas, de integridade, de datas, do crontab, do banco de dados e (com `scanlog=`) dos logs de acesso, depois a varredura por assinaturas de malware, e **não altera nada**. No modo texto os achados são reunidos e impressos de uma vez no fim, do mais grave ao mais leve; com `format=json` eles saem à medida que cada scanner os produz. Só um modo de varredura é aceito por execução.

Para corrigir o que foi encontrado:

```
php bin/facheiro.php dryrun=1 scandirectory=/path/to/site   # simula a limpeza por assinaturas, não grava nada
php bin/facheiro.php scandirectory=/path/to/site            # remove malware conhecido dos arquivos infectados
php bin/facheiro.php allfiles=1 scandirectory=/path/to/site # ... examinando todos os arquivos, não só as extensões de risco
php bin/facheiro.php scanintegrity=1 restore=1 dryrun=1 scandirectory=/path/to/wp-root  # simula a restauração
php bin/facheiro.php scanintegrity=1 restore=1 quarantinedir=/safe/place scandirectory=/path/to/wp-root
```

A limpeza por assinaturas é o modo padrão, então sem nenhuma opção de modo o script modifica arquivos; `dryrun=1` é a chave que o torna só de relatório. (`allfiles=1` se chamava `scan_all=1` em versões anteriores; o nome antigo agora para com um erro, porque era fácil demais confundi-lo com `scanall=1`.)

Para rodar um scanner de cada vez:

```
php bin/facheiro.php scancron=1               # procura malware no crontab do usuário atual
php bin/facheiro.php scanlog=/var/log/apache2/access.log   # procura IoCs em um log de acesso
php bin/facheiro.php scanlog=/var/log/apache2 # examina todos os logs de acesso de uma pasta (.gz incluídos)
php bin/facheiro.php scanlog=/var/log/apache2 correlate=1 scandirectory=/path/to/wp-root  # liga o tráfego aos arquivos
php bin/facheiro.php scanintegrity=1 scandirectory=/path/to/wp-root   # confere core, plugins e temas
php bin/facheiro.php scanintegrity=1 checksumdir=/path/to/manifests   # ... sem acesso à rede
php bin/facheiro.php scanintegrity=1 locale=pt_BR scandirectory=/path/to/wp-root  # core que não é em inglês
php bin/facheiro.php scantimes=1 scandirectory=/path/to/wp-root       # relatório de anomalias de datas
php bin/facheiro.php scandb=1 scandirectory=/path/to/wp-root          # varredura do banco de dados (só leitura)
php bin/facheiro.php quickscan=1 scandirectory=/path/to/wp-root       # PHP em uploads, ganchos prepend, mu-plugins
php bin/facheiro.php help=1                   # mostra o uso
```

**Pasta de conteúdo movida.** Plugins, temas, uploads e mu-plugins são procurados onde o WordPress os carrega, e não só em `<raiz>/wp-content`. Dentro do WordPress (painel, WP-CLI, assistentes) o plugin passa `WP_CONTENT_DIR` e `WP_PLUGIN_DIR`, e a página de recuperação passa a pasta de plugins de onde ela roda. A CLI independente lê `WP_CONTENT_DIR` e `WP_PLUGIN_DIR` do `wp-config.php` quando são uma string simples, ou `__DIR__`, `dirname(__FILE__)` ou `ABSPATH` seguidos de uma string; qualquer outra coisa (o `Config::define()` do Bedrock, variáveis, `getenv()`) precisa de `contentdir=/path` (e de `plugindir=/path` quando os plugins ficam em outro lugar). Uma pasta fora da raiz é percorrida por todos os scanners, e `<raiz>/wp-content` também é escaneada sempre que existe. Uma pasta realocada que foi encontrada gera `CONTENT_DIR` (INFO), para o relatório dizer onde olhou. Uma que não pode ser encontrada, um define que não pode ser avaliado, ou um define apontando para `/`, para a raiz ou para uma das pastas acima dela (um `wp-config.php` adulterado pode apontar para qualquer lugar) gera `CONTENT_DIR_UNKNOWN` (ERROR). Uma execução de limpeza ou restauração nunca segue um define do `wp-config.php` para fora da raiz (o arquivo pode ser gravado pelo invasor, e o operador pode estar rodando com mais privilégios que o usuário web): ela relata `CONTENT_DIR_UNKNOWN` até que `contentdir=` confirme a pasta, ou que `dryrun=1` torne a execução só de relatório.

`scandirectory=` assume o diretório atual por padrão. A varredura por assinaturas e `correlate=1` aceitam qualquer diretório; `scanintegrity`, `scantimes`, `quickscan`, `scandb` e `scanall` precisam da raiz do WordPress (o diretório que contém `wp-includes/`) e param com um erro caso contrário. Os argumentos são interpretados como uma query string de URL, então coloque entre aspas os caminhos que contêm espaços ou `&`, e escreva `+` como `%2B` e `%` como `%25` (um `+` literal seria lido como espaço). A varredura do banco lê as credenciais do `wp-config.php` com expressões regulares e nunca o executa.

**Sempre faça um backup antes de limpar.** `dryrun=1` é o jeito seguro de ver antes o que mudaria.

## Saída

Todos os scanners relatam os achados num único formato, fácil de filtrar com grep, ordenar e colar num chamado. O formato e os detalhes dos achados são em inglês em qualquer idioma:

```
SEVERITY,TYPE,path,detail
```

Os três primeiros campos nunca contêm vírgulas; tudo depois da terceira vírgula é detalhe em formato livre. Como os caminhos e o conteúdo dos logs vêm de um servidor comprometido, `%`, caracteres de controle e (no campo do caminho) vírgulas são codificados com `%`, de modo que um nome de arquivo forjado não consegue deslocar campos nem injetar linhas falsas de achado. As gravidades são `HIGH`, `MEDIUM`, `LOW`, `INFO` e `ERROR`. Linhas recuadas abaixo de um achado são contexto de apoio (linhas de log de exemplo, principais IPs de origem). Por exemplo:

```
HIGH,MALWARE_CLEANED,/path/to/file.js,javascript_ndsw
HIGH,MALWARE_FOUND,/path/to/file.js,javascript_ndsw (dry run: file not modified)
HIGH,MALWARE_FOUND,/path/to/link.js,javascript_ndsw (symbolic link to /shared/file.js: never modified, clean the file it points to)
HIGH,CRONTAB_IOC,crontab,crontab.tmp.006: * * * * * echo ... | base64 --decode > /tmp/x
MEDIUM,LOG_IOC,/var/log/apache2/access.log,access.xmlrpc.flood: 4182 hit(s) - High volume of xmlrpc.php POSTs, ...
```

IoCs de log saem como `MEDIUM` (tentativas de ataque, inclusive as que falharam), exceto o tráfego para um shell que já está no disco, que é `HIGH`. Assinaturas ruidosas por natureza (por exemplo, POSTs em `wp-login.php`) só disparam acima de um limite de volume, para que o tráfego normal não gere alarmes.

### Saída em JSON e códigos de saída

`format=json` (CLI) ou `--format=json` (WP-CLI) troca o stdout para NDJSON: um objeto de evento por linha, com os valores crus (escapados em JSON):

```
{"event":"finding","severity":"HIGH","type":"LOG_IOC","path":"...","detail":"...","context":["e.g. ..."]}
{"event":"summary","scan":"integrity","MODIFIED":1,"MISSING":0,...}
```

Bytes que não são UTF-8 válido (um nome de arquivo, uma linha de log, um valor do banco cortado no meio de um caractere) não cabem em JSON: eles viram U+FFFD na saída JSON, na tabela do painel e no modo de recuperação, de modo que o achado continua sendo relatado. A saída em texto imprime os bytes crus.

O progresso e os textos informativos vão para o stderr, então o stdout traz apenas eventos legíveis por máquina, prontos para pipelines. Um erro de uso ou fatal (argumentos inválidos, alvo ilegível, banco inacessível em `scandb=1`) é emitido como `{"event":"error","detail":"..."}` antes de sair com 1, de modo que o fluxo nunca carrega texto solto. A exportação JSON do painel usa os mesmos eventos de achado.

Tudo o que impede uma verificação vira um achado `ERROR` (saída 2), nunca um pulo silencioso:

- uma pasta de conteúdo que não pode ser localizada: `CONTENT_DIR_UNKNOWN`;
- dentro do `scanall`, um banco inacessível: `DB_UNAVAILABLE`; uma consulta que falha: `DB_QUERY_FAILED`;
- um arquivo ilegível: `INTEGRITY_UNREADABLE` (ou, na varredura por assinaturas, `FILE_UNREADABLE`); uma pasta que não pode ser listada gera os mesmos dois tipos (antes ela era pulada);
- um link simbólico para uma pasta que uma execução capaz de modificar arquivos não seguiu: `SYMLINK_NOT_FOLLOWED`;
- checksums de referência que não puderam ser baixados ou lidos: `INTEGRITY_NO_REFERENCE` como `ERROR` (como `INFO`, significa que não existe referência oficial para aquele pacote, ou que não há nenhuma em `checksumdir=`);
- numa rede multisite, uma lista de sites que não pôde ser lida, ou um site cujas tabelas estão faltando: `DB_QUERY_FAILED`, com o nome da tabela;
- um arquivo PHP acima do limite de 2 MB da varredura por assinaturas: `FILE_TOO_LARGE` (arquivos maiores que não são PHP geram o mesmo tipo como `INFO`);
- uma assinatura cuja regex o motor PCRE desistiu de avaliar num arquivo (limite de backtrack, de recursão ou da pilha do JIT): `SIGNATURE_ERROR`;
- um log que não pode ser aberto ou descompactado: `LOG_UNREADABLE`;
- um crontab que não pode ser lido (sem `shell_exec`, sem o binário `crontab`): `CRONTAB_UNAVAILABLE`.

Um relatório limpo significa que todos os scanners de fato olharam.

O código de saída reflete o pior achado, para que tarefas de cron e CI possam alertar com base nele: **0** limpo (ou só INFO), **1** erro de uso ou fatal, **2** achados LOW/MEDIUM/ERROR, **3** achados HIGH. Repare que uma limpeza bem-sucedida também sai com 3: havia malware.

## O que ele examina

- **Arquivos**: detecção e limpeza, por assinaturas, de injeções de malware conhecidas (por exemplo, as campanhas JavaScript `ndsw`/`ndsx` e `wqpq`), nas extensões web comuns (`php`, `js`, `html`, ...). Os arquivos limpos são gravados de forma atômica (arquivo temporário + rename), então uma gravação que falha nunca trunca o original. A pasta do próprio plugin nunca é escaneada. Um **conjunto de detecção** embutido, com cerca de 35 formatos genéricos de webshell e backdoor, relata `MALWARE_FOUND` e nunca limpa, nem numa execução real: código ou comandos de shell vindos da requisição (`eval($_POST[...])`, `system($_GET[...])`, entrada da requisição usada como callback ou caminho de include), gravações de arquivo com nome vindo da requisição e uploaders que mantêm o nome de arquivo do cliente (as formas mais frouxas, por um caminho ou uma variável, só em arquivos sem nenhuma verificação de capability, nonce ou upload do WordPress), shells protegidos por senha, famílias de shell conhecidas (WSO/FilesMan, b374k, c99, r57, IndoXploit, Alfa), WP-VCD, NDSW com variáveis renomeadas, PHP atrás de um cabeçalho de imagem, includes de ícones/imagens ou de caminhos em códigos de escape, e ofuscação (`eval` da saída de `base64_decode`/`gzinflate`, regexes com `/e`, nomes de função invertidos ou em rot13, nomes em escape hexadecimal, cadeias de `chr()`, ofuscadores com o array `$GLOBALS`, chamadas dinâmicas de uma linha). HIGH significa um destino perigoso alimentado direto pela requisição, uma proteção por senha ou uma família conhecida; MEDIUM é ofuscação de que código legítimo quase nunca precisa. Um arquivo em que nada bateu ganha uma segunda olhada com os comentários removidos, fragmentos `'ev'.'al'` e acréscimos com `.=` unidos, `${"_POST"}` lido como `$_POST` e escapes de letras decodificados. Os formatos foram modelados no que php-malware-finder, AMWScan, signature-base, o scanner do scr34m e o Linux Malware Detect têm em comum, e são testados contra falsos positivos no core do WordPress e em cerca de 2.200 plugins e 550 temas populares do wordpress.org: o que ainda bate lá são plugins que executam, por projeto, PHP enviado a eles (Ad Inserter, VaultPress), as strings do scanner de um plugin antispam e um comentário de documentação.
- **Crontab**: roda `crontab -l` para o usuário que executa o PHP e procura padrões conhecidos de persistência (decodificadores base64 encadeados por pipe, downloads do pastebin, droppers em diretórios tmp). Os crontabs de outros usuários e `/etc/cron.*` não são cobertos; se o comando não puder rodar, `CRONTAB_UNAVAILABLE` avisa.
- **Logs de acesso**: tráfego de ataque conhecido: requisições a webshells, arquivos PHP servidos de `wp-content/uploads`, tentativas de exploit do wp-file-manager / Slider Revolution / TimThumb, sondagens de `.env`, travessia de diretórios, injeção de código e de PHP-CGI, enumeração de usuários e enxurradas de força bruta em xmlrpc/wp-login. A correlação (`correlate=1` / `--correlate`, automática no `scanall`) também relata os arquivos cuja data de modificação cai dentro de `window` segundos (300 por padrão) do tráfego apontado: `LOG_FILE_CORRELATION`, o vestígio de "esta requisição criou aquele arquivo". Uma correspondência é uma pista forte; a ausência dela não inocenta nada, já que edições posteriores ou datas falsificadas apagam o vínculo.
- **Integridade**: confere o core do WordPress, cada plugin e cada tema com os pacotes oficiais do wordpress.org da versão instalada. O idioma do core é o que a instalação indica em `wp-includes/version.php` (um pacote localizado define `$wp_local_package` ali, e os arquivos traduzidos do core só batem com os checksums daquele idioma); `locale=xx_XX` / `--locale` o substitui. Relata `INTEGRITY_MODIFIED` (checksum diferente), `INTEGRITY_MISSING` (arquivo do pacote que sumiu) e `INTEGRITY_EXTRA` (arquivo no disco que o pacote não contém: PHP sobrando dentro do core ou de um plugin é o clássico webshell plantado e sai como `HIGH`; sobras normalmente legítimas, como `error_log` e o bootstrap do WAF do Wordfence, saem como `INFO` com uma explicação). Pacotes que não podem ser conferidos (plugins e temas personalizados ou premium, temas filhos, versões fora do arquivo) saem como `INTEGRITY_NO_REFERENCE`, então um relatório limpo nunca significa, em silêncio, "não verificado". O core e os plugins usam as APIs de checksums; os temas não têm API de checksums, então o manifesto é montado calculando os hashes do zip oficial do tema (exige a extensão zip do PHP). Temas e plugins que vêm junto em `wp-content` são pulados na passada do core, e o `wp-config.php` é ignorado.
- **Verificações rápidas**: os esconderijos baratos e reveladores dos invasores: PHP executável dentro de `wp-content/uploads` (`UPLOADS_PHP`, HIGH), diretivas `auto_prepend_file`/`auto_append_file` em `.user.ini`/`php.ini`/`.htaccess`, que executam um arquivo a cada requisição (`PHP_PREPEND`; o bootstrap do WAF do Wordfence é reconhecido e sai como INFO), um inventário dos mu-plugins, que carregam sem etapa de ativação (`MU_PLUGIN`, INFO), e PHP oculto em arquivos com ponto (`HIDDEN_PHP`).
- **Banco de dados**: varredura só de leitura (apenas SELECT).
  - *Contas e papéis.* Um inventário das contas de administrador (`DB_ADMIN_USER`, INFO; confirme cada uma), com os administradores criados nos últimos 30 dias elevados a `DB_NEW_ADMIN` (MEDIUM, o vestígio clássico de tomada de controle), e papéis que não são de administrador mas receberam poderes de tomada de controle, como `manage_options`/`edit_users`, na opção `user_roles` (`DB_ROLE_CAPS`, MEDIUM; plugins editores de papéis e papéis de gerente de loja fazem isso legitimamente, então verifique em vez de presumir).
  - *Opções e posts.* Valores de opção injetados (`DB_OPTION_IOC`: PHP/eval, iframes ocultos, JS ofuscado, scripts remotos), sequestro de `siteurl`/`home` (`DB_SITE_URL`) e adulteração de `active_plugins` (`DB_ACTIVE_PLUGIN`: travessia de caminho ou entradas que não existem no disco); e injeções de script/PHP no conteúdo de posts (`DB_POST_IOC`, encontradas com um pré-filtro `LIKE` no servidor, para a tabela de posts não ser trazida inteira; as revisões são puladas, então cada post injetado é relatado uma vez).
  - *Sem unserialize.* Todo valor é apenas comparado com padrões e **nunca passa por `unserialize()`**: dados serializados hostis podem disparar uma injeção de objeto PHP.
  - *Quando o banco não responde.* Na CLI independente, se o mysqli estiver ausente, se as credenciais não puderem ser lidas (configurações no estilo `getenv()` não podem ser interpretadas sem executá-las) ou se o banco estiver inacessível, `scandb=1` sai com 1 e um erro, enquanto `scanall=1` relata `DB_UNAVAILABLE` (ERROR) e continua; uma consulta que falha no meio da varredura relata `DB_QUERY_FAILED` para aquela tabela.
  - *Redes multisite.* Numa **rede multisite** todos os sites são escaneados, seja qual for o site de onde a varredura partiu: os sites são listados de `{prefix}blogs` um lote por vez (assim uma rede com dezenas de milhares de sites é percorrida com uma fila curta e pode pausar e continuar), e as tabelas de opções e de posts de cada site (`{prefix}{id}_options`, `{prefix}{id}_posts`), a opção de papéis dele (`{prefix}{id}_user_roles`) e os administradores dele (`{prefix}{id}_capabilities` na `usermeta` compartilhada) passam pelas mesmas verificações, com o caminho do achado nomeando a tabela do site e os achados de administrador dizendo `administrator of site N`. As configurações da própria rede em `{prefix}sitemeta` também são escaneadas: os super administradores (`DB_SUPER_ADMIN`, INFO; cada um controla todos os sites, então confirme cada um; um criado nos últimos 30 dias é um `DB_NEW_ADMIN`, um login que está na lista sem conta de usuário por trás é LOW, porque quem registrar esse nome vira super administrador, e uma lista ausente ou ilegível é relatada, em vez de ser tomada como "nenhum super administrador"), os plugins ativados na rede (`active_sitewide_plugins`, com as mesmas verificações `DB_ACTIVE_PLUGIN` de `active_plugins`) e os valores injetados (`DB_OPTION_IOC`). O limite da listagem de posts (100 posts apontados) conta por site. Um site listado em `{prefix}blogs` cujas tabelas estão faltando relata `DB_QUERY_FAILED` para cada uma delas, e o mesmo vale para uma lista de sites que não pode ser lida, dizendo depois de qual id os sites não foram escaneados.
- **Datas de modificação**: heurísticas só de relatório para arquivos mexidos fora do ritmo do pacote a que pertencem. Cada verificação procura um ponto fora da curva *dentro* de um pacote (o core, um plugin, um tema), nunca uma comparação com uma data do site inteiro, que se afogaria em falsos positivos depois de qualquer migração. `TIMESTAMP_OUTLIER` aponta um punhado de arquivos modificados depois do grupo dominante de instalação/atualização do pacote (o clássico `functions.php` com backdoor, ou um loader plantado); um grupo grande e mais novo é uma atualização legítima e não é apontado. `TIMESTAMP_TIMESTOMP` aponta arquivos PHP cuja data de modificação está muito atrás da data de alteração do inode: `touch -t` consegue recuar a data do conteúdo, mas a data de alteração do inode não pode ser definida sem root. E só aponta quando poucos arquivos do pacote mostram isso, já que migrações e `rsync -a` fazem o mesmo com árvores inteiras. Datas são pistas, não provas: invasores as falsificam e atualizações as reescrevem, então esses achados nunca alimentam uma ação de limpeza, e um resultado limpo não inocenta um arquivo.

### Restauração de arquivos

Com `scanintegrity=1 restore=1` (CLI) ou `wp facheiro integrity --restore`, cada arquivo `INTEGRITY_MODIFIED` e `INTEGRITY_MISSING` é restaurado a partir do zip do pacote oficial da versão exata instalada. Garantias de segurança:

- **Faça um backup antes**, e simule com `dryrun=1` / `--dryrun` (relata `INTEGRITY_RESTORABLE` sem gravar).
- Cada arquivo é **conferido byte a byte com o manifesto de checksums de referência antes de ser gravado**: um zip adulterado ou que não confere é recusado (`RESTORE_FAILED`), nunca gravado.
- Arquivos `EXTRA` **nunca são tocados**: apagar arquivos desconhecidos é decisão do operador.
- Toda gravação **fica dentro do diretório do pacote**: uma entrada do manifesto ou do zip que não seja um caminho relativo simples é recusada, um destino que seja um link simbólico é recusado, e uma pasta de destino que resolva (por um link simbólico plantado) para fora da árvore do plugin, do tema ou do core é recusada, cada caso como `RESTORE_FAILED`. Cabeçalhos de versão que não sejam strings de versão simples tornam o pacote `INTEGRITY_NO_REFERENCE`, em vez de chegarem a uma URL ou a um nome de arquivo.
- Sobrescrever um arquivo com backdoor destrói evidência. Defina `quarantinedir=/path` / `--quarantine-dir` (fora da raiz web) para copiar cada original como `*.quarantine` antes de ele ser sobrescrito; se a quarentena falhar, o arquivo é deixado como está.
- Offline: com `checksumdir=` / `--checksum-dir`, os zips dos pacotes são lidos como `core-{version}.zip` / `plugin-{slug}-{version}.zip` / `theme-{slug}-{version}.zip` do mesmo diretório. A restauração do core em idiomas diferentes de `en_US` ainda não é suportada (a restauração de plugins e temas independe do idioma).

### Verificação de integridade sem acesso à rede

Em servidores sem saída para a rede, baixe os dados de referência em outra máquina, coloque tudo em um diretório e passe `checksumdir=/path` (`--checksum-dir`). Com essa opção definida a ferramenta nunca toca a rede: o que faltar no diretório sai como `INTEGRITY_NO_REFERENCE`.

```
core-{version}.json           de https://api.wordpress.org/core/checksums/1.0/?version={version}&locale={locale}
plugin-{slug}-{version}.json  de https://downloads.wordpress.org/plugin-checksums/{slug}/{version}.json
theme-{slug}-{version}.zip    de https://downloads.wordpress.org/theme/{slug}.{version}.zip
```

Os temas não têm API de checksums, então conferi-los offline exige o próprio zip do pacote do tema (e a extensão zip do PHP). O manifesto do core leva só a versão no nome: para um site que não é em inglês, baixe-o com o seu idioma na URL e salve mesmo assim como `core-{version}.json`. Para restaurações, acrescente `core-{version}.zip` e `plugin-{slug}-{version}.zip` (de `https://wordpress.org/wordpress-{version}.zip` e `https://downloads.wordpress.org/plugin/{slug}.{version}.zip`); o zip do tema já cobre as restaurações de tema.

A verificação TLS fica ligada em todas as requisições às APIs: esta ferramenta roda em servidores já comprometidos, e um "tudo limpo" não pode vir de um invasor.

## Como adicionar assinaturas

As assinaturas de limpeza de arquivos ficam em `Signatures::builtin_cleanup()`, em `includes/engine/signatures.php`, indexadas por um nome único (o conjunto de detecção, só de relatório, é `Signatures::builtin_detection()`, com a ação `array('detect' => SEVERITY, 'description' => ...)`; cada uma precisa de um fixture `pos--<nome>` em `tests/fixtures/detection/`):

```php
'javascript_example' => array(
    // Cheap check run first on every file: array('string' => needle) for a
    // fast strpos lookup (preferred), or array('regex' => pattern).
    'prefilter' => array('string' => 'example-malware-marker'),
    // Zero or more further conditions that must ALL also match. The
    // prefilter already counts, so don't repeat it here.
    'triggers'  => array(
        array('regex' => '/eval\(example_\w+\(/'),
    ),
    // What to do with a confirmed file: remove every match of a pattern,
    // or delete the file outright.
    'action'    => array('remove_regex' => '/eval\(example_\w+\([^;]+;/s'),
    // 'action' => array('delete_file' => true),
),
```

### Assinaturas personalizadas

Assinaturas específicas de um site não exigem mudança no código. Escreva-as na aba Assinaturas do plugin ou num arquivo JSON, o mesmo formato que a aba exporta. **[Writing malware signatures](docs/writing-signatures.md)** (em inglês) é o guia completo: o que cada alvo enxerga, como transformar uma amostra em regra, como mantê-la rápida e sem falsos positivos, testes, compartilhamento e exemplos resolvidos ([`docs/examples/signatures.json`](docs/examples/signatures.json)).

```json
{"facheiro_signatures": 1, "signatures": [
  {"id": "acme-loader", "target": "file", "severity": "HIGH", "description": "ACME loader backdoor",
   "match": [{"string": "acme_loader"}, {"regex": "/eval\\s*\\(\\s*\\$/"}]},
  {"id": "casino-spam", "target": "db_post", "severity": "LOW", "pattern": "@casino-bonus\\.example@i"}
]}
```

`target` é `file`, `db_option` ou `db_post`. Assinaturas de arquivo listam de 1 a 10 condições que precisam bater todas, sendo a primeira o pré-filtro. Assinaturas de banco de dados levam um único `pattern`; as de post enxergam o conteúdo de todo post ativo (com uma assinatura personalizada de post instalada, a varredura lê todos os posts, e não só os que têm marcas parecidas com código). Uma assinatura personalizada sempre só relata, como `SIGNATURE_MATCH` para arquivos, com a gravidade que ela mesma define, e nunca limpa, nem numa execução real de `wp facheiro scan`. As assinaturas embutidas são verificadas primeiro. Uma regex que não compila, ou que bate numa string vazia, é recusada. A CLI independente aceita o mesmo arquivo:

```
php bin/facheiro.php scanall=1 scandirectory=/var/www/html signatures=/path/signatures.json
```

As regexes são padrões PCRE completos, com delimitadores e flags. Todo padrão (incluindo os conjuntos de crontab, logs de acesso e banco de dados) é compilado para conferência antes de a varredura começar, então uma regex malformada interrompe a execução e nomeia a assinatura quebrada, em vez de nunca bater em silêncio. `remove_regex` falha com alarde se não bateu em nada, e a simulação cobre os dois tipos de ação.

## Traduções

O texto do próprio plugin é em português do Brasil: esse é o idioma das strings no código-fonte, sob o text domain `facheiro`. O inglês vem em `languages/` (`facheiro-en_US.po`, compilado em `.mo` e `.l10n.php`) e é mostrado a todo usuário cujo idioma seja alguma variante do inglês; qualquer outro idioma vê o texto em português. Pacotes de idioma do translate.wordpress.org, quando o plugin estiver no diretório, têm precedência. A página de recuperação roda sem o WordPress, então tem a própria tabela, `includes/recovery/i18n/en.php` (texto em português => inglês); ela escolhe o idioma pelo navegador e oferece a troca no cabeçalho. Os detalhes dos achados, que vêm do motor, ficam em inglês em todo lugar, como a saída da CLI e as exportações; `includes/recovery/i18n/pt_BR.php` só traduz os nomes das etapas do motor para a página de recuperação.

Depois de alterar strings da interface, atualize o modelo e a tradução para o inglês (WP-CLI 2.8+):

```
wp i18n make-pot . languages/facheiro.pot --slug=facheiro --domain=facheiro \
    --exclude=tests,site,vendor,node_modules,includes/engine,includes/recovery,bin
wp i18n update-po languages/facheiro.pot languages/facheiro-en_US.po   # depois traduza as entradas novas para o inglês
wp i18n make-mo languages && wp i18n make-php languages
```

Uma string acrescentada à página de recuperação é escrita em português, passa por `App::t()` / `App::e()` e precisa da linha em inglês correspondente em `includes/recovery/i18n/en.php`; mantenha os marcadores (`%s`, `%1$s`, `%d`) idênticos.

Este README também tem as duas versões: `README.md` em português e `README.en.md` em inglês. Ao mudar uma, mude a outra.

## Desenvolvimento

```
includes/engine/   o motor de varredura (namespace Facheiro\Engine, sintaxe do PHP 5.6, sem depender do WordPress)
includes/plugin/   o lado WordPress (PHP 7.2+): página do painel, WP-CLI, adaptadores de $wpdb e da API HTTP
bin/facheiro.php  a entrada da CLI independente
tests/regress.sh   diff da saída antiga contra a nova sobre fixtures sintéticos (os casos de banco precisam do fixture MariaDB)
tests/chunking.php prova que uma varredura rodada uma unidade por requisição dá os mesmos achados que uma execução ininterrupta
tests/admin-ui.js  Playwright percorrendo a página do painel
tests/background-ui.js, findings-ui.js, signatures-ui.js   Playwright: execução/agendamento, falsos positivos e amostras, editor de assinaturas
tests/hardening-ui.js   Playwright: aba Blindagem num site Apache (aplicar, verificar, download do Nginx, remover)
tests/recovery.js  Playwright: chave de recuperação, página de recuperação num site quebrado, varredura, exportação, revogação
tests/mcp-stdio.js sessão de cliente MCP por STDIO através do MCP Adapter
tests/checksums.sh o checksums.json está em dia; a autoverificação numa cópia parecida com um release
tests/tamper.sh    configurações seladas num site de teste (WP-CLI); tests/tamper-ui.js: os avisos de revisão
build/make-checksums.php   grava o checksums.json (rode depois de alterar qualquer arquivo distribuído)
build/make-zip.php         monta o dist/facheiro.zip, o pacote de release
.claude/skills/pre-share-check/   skill do Claude Code: confere as mudanças de um branch antes de serem compartilhadas (roda as verificações acima, revisa o diff, não altera nada)
recovery.php, includes/recovery/   modo de recuperação (roda sem o WordPress; sintaxe do PHP 5.6)
site/              a página do projeto (HTML estático, fora do zip do plugin)
```

As suítes Playwright conferem o texto em inglês, então rode-as num site cujo idioma seja o inglês.

O `.distignore` lista o que fica fora do pacote do WordPress.org (testes, ferramentas, documentação para quem contribui, a página do projeto); o `.gitattributes` deixa os mesmos arquivos fora do `git archive` e do Download ZIP do GitHub, e o `build/make-checksums.php` se recusa a rodar quando as duas listas divergem. Monte o pacote com `php build/make-zip.php`: ele grava o `dist/facheiro.zip` com exatamente os arquivos listados em `files` no `checksums.json`, cada um conferido com o seu checksum, e se recusa quando o `checksums.json` está desatualizado. Esse zip é o que se envia ao WordPress.org, se instala num site de teste e se passa pelo Plugin Check. Um checkout do git não é um release: o Plugin Check relata `tests/`, `build/`, `.claude/`, `CLAUDE.md` e afins como `application_detected`, `hidden_files`, `ai_instruction_directory`, `unexpected_markdown_file` e PHP sem proteção.

`composer install` traz o PHPCS com os padrões do WordPress e do PHPCompatibility; `composer phpcs` precisa voltar limpo antes de um release. O `TESTPLAN.md` lista os fixtures e os testes ao vivo contra o wordpress.org, que precisam de um site com acesso à rede.

## Limitações

- Baseado em assinaturas: ele encontra e remove malware *conhecido* e relata os formatos comuns de backdoor. Loaders em vários estágios, disparadores de e-mail e gerenciadores de arquivos sem um destino perigoso evidente ainda passam. Uma varredura limpa não prova que o site está limpo.
- As verificações de IoC nos logs mostram *tentativas* de ataque, inclusive muitas que falharam (status 403/404). Trate-as como alerta e ponto de partida para a investigação, não como confirmação de invasão.
- Uma regex de assinatura que o motor PCRE desiste de avaliar num arquivo (`pcre.backtrack_limit`, `pcre.recursion_limit`, a pilha do JIT) é relatada como `SIGNATURE_ERROR`, com o nome da assinatura, e nunca tomada como "não bateu". O conjunto embutido foi escrito para isso não acontecer; uma assinatura personalizada com repetições aninhadas (`(a+)+`) pode provocar.
- O scanner de arquivos não lê arquivos maiores que 2 MB. Cada um é relatado como `FILE_TOO_LARGE`: `INFO` para JavaScript, CSS e outros arquivos que não são PHP (o core do WordPress traz vários bundles desse tamanho), `ERROR` para PHP, em que um arquivo tão grande é incomum. Revise esses à mão ou com `scanintegrity=1`.
- Uploads e mu-plugins são esperados dentro da pasta de conteúdo. Um site que os move separadamente (a constante `UPLOADS`, a opção `upload_path`, `WPMU_PLUGIN_DIR`) ainda os tem escaneados por assinaturas quando ficam dentro da raiz, mas `UPLOADS_PHP` e `MU_PLUGIN` não os reconhecem ali.
- Varreduras só de relatório seguem um link simbólico para uma pasta (uma pasta de uploads ligada, um deploy no estilo releases), mas nunca para uma pasta acima, para a raiz do sistema de arquivos ou duas vezes para a mesma pasta. Uma execução que pode modificar arquivos (a varredura por assinaturas sem `dryrun`) não os segue: cada um é relatado como `SYMLINK_NOT_FOLLOWED` e precisa ser escaneado à parte.
- Numa rede multisite a varredura do banco cobre os sites listados em `{prefix}blogs` (arquivados, marcados como spam e apagados mas ainda não purgados incluídos). Tabelas deixadas por um site que não está mais na lista não são lidas. A CLI independente e o modo de recuperação reconhecem uma rede por um `define( 'MULTISITE', true );` literal no `wp-config.php`, como o WordPress o escreve; uma configuração que o defina de qualquer outro jeito é escaneada como site único. Uma lista de super administradores definida em código (`$super_admins` no `wp-config.php`) não é vista: a varredura relata a que está no banco. Quando um banco guarda várias redes (linhas de `sitemeta` sob mais de um `site_id`), as listas de super administradores delas são relatadas juntas, sem dizer a qual rede cada uma pertence. Com um site por banco (configurações no estilo HyperDB) a CLI independente relata as tabelas que não encontra como `DB_QUERY_FAILED`; nesses casos, faça a varredura pelo WordPress.
- As varreduras são só de relatório nesta versão; a limpeza e a restauração rodam pela linha de comando. As páginas do painel só alteram arquivos quando você aplica regras de blindagem (`.htaccess`) ou cria uma chave de recuperação.
- As regras de blindagem são gravadas apenas para Apache/LiteSpeed; a configuração do Nginx precisa ser incluída por alguém com acesso ao servidor. O IIS não é suportado.
- A verificação de blindagem não consegue distinguir uma recusa do servidor web de uma recusa de um firewall ou CDN na frente do site.
- O acesso de assistentes de IA precisa do WordPress 6.9+ e do plugin MCP Adapter. O que você compartilha com um assistente vai para o provedor dele.
- Varreduras em segundo plano e agendadas dependem do WP-Cron: o site precisa conseguir requisitar o próprio `wp-cron.php`, ou uma tarefa de cron do servidor precisa chamá-lo. A página passa a avançar a varredura por conta própria quando o WP-Cron para de responder.

## Licença

GPLv2 ou posterior. Veja `LICENSE`.
