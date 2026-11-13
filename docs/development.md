# Desenvolvimento

<p><a href="development.en.md">Read in English</a></p>

Este documento é para quem mexe no código do Facheiro. Para usar o plugin, comece pelo [README](../README.md) e pelos guias da [wiki](https://github.com/fcavallari/Facheiro/wiki).

## Onde fica cada documentação

| Documento | O que traz | Quando atualizar |
|---|---|---|
| `README.md`, `README.en.md` | visão geral, instalação, primeiros passos, links | quando isso mudar |
| [Wiki](https://github.com/fcavallari/Facheiro/wiki) | os guias de uso: plugin e WP-CLI, blindagem, modo de recuperação, detecção de adulteração, assistentes de IA, CLI independente, restauração, assinaturas personalizadas, limitações | depois do merge (a wiki é um repositório à parte, `Facheiro.wiki.git`, e não acompanha os branches) |
| `site/referencia/`, `site/en/reference/` | a referência: formato da saída, eventos JSON, códigos de saída, achados `ERROR`, o que cada scanner examina, extensões do PHP | no mesmo commit que o código: é o contrato de saída que o `tests/regress.sh` protege (publicar o site é um passo à parte) |
| `docs/writing-signatures.md` | o guia de assinaturas personalizadas (em inglês) | quando o formato das assinaturas mudar |
| `docs/development.md`, `docs/development.en.md` | este documento | no mesmo commit que o código |
| `readme.txt` | a página do plugin no WordPress.org | quando o que o usuário vê mudar |

Tudo, exceto `docs/writing-signatures.md` e `readme.txt`, existe em português e em inglês: ao mudar uma versão, mude a outra. Na wiki cada página em português tem uma correspondente em inglês, ligadas no topo.

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
site/              a página do projeto e a referência (HTML estático, fora do zip do plugin)
```

As suítes Playwright conferem o texto em inglês, então rode-as num site cujo idioma seja o inglês.

O `.distignore` lista o que fica fora do pacote do WordPress.org (testes, ferramentas, documentação para quem contribui, a página do projeto); o `.gitattributes` deixa os mesmos arquivos fora do `git archive` e do Download ZIP do GitHub, e o `build/make-checksums.php` se recusa a rodar quando as duas listas divergem. Monte o pacote com `php build/make-zip.php`: ele grava o `dist/facheiro.zip` com exatamente os arquivos listados em `files` no `checksums.json`, cada um conferido com o seu checksum, e se recusa quando o `checksums.json` está desatualizado. Esse zip é o que se envia ao WordPress.org, se instala num site de teste e se passa pelo Plugin Check. Um checkout do git não é um release: o Plugin Check relata `tests/`, `build/`, `.claude/`, `CLAUDE.md` e afins como `application_detected`, `hidden_files`, `ai_instruction_directory`, `unexpected_markdown_file` e PHP sem proteção.

`composer install` traz o PHPCS com os padrões do WordPress e do PHPCompatibility; `composer phpcs` precisa voltar limpo antes de um release. O `TESTPLAN.md` lista os fixtures e os testes ao vivo contra o wordpress.org, que precisam de um site com acesso à rede.
