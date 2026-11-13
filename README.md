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

## Documentação

- **[Wiki](https://github.com/fcavallari/Facheiro/wiki)**, os guias de uso: [o plugin e o WP-CLI](https://github.com/fcavallari/Facheiro/wiki/Plugin-e-WP-CLI), [blindagem](https://github.com/fcavallari/Facheiro/wiki/Blindagem), [modo de recuperação](https://github.com/fcavallari/Facheiro/wiki/Modo-de-recuperação), [detecção de adulteração](https://github.com/fcavallari/Facheiro/wiki/Detecção-de-adulteração), [assistentes de IA](https://github.com/fcavallari/Facheiro/wiki/Assistentes-de-IA), [CLI independente](https://github.com/fcavallari/Facheiro/wiki/CLI-independente), [restauração e integridade offline](https://github.com/fcavallari/Facheiro/wiki/Restauração-e-integridade-offline), [assinaturas personalizadas](https://github.com/fcavallari/Facheiro/wiki/Assinaturas-personalizadas) e [limitações](https://github.com/fcavallari/Facheiro/wiki/Limitações).
- **[Referência](https://facheiro.space.fast/referencia/)**: o formato da saída, os eventos JSON, os códigos de saída, o que cada scanner examina e as extensões do PHP de que cada um precisa.
- **[Writing malware signatures](docs/writing-signatures.md)** (em inglês): como escrever e testar assinaturas personalizadas.
- **[Desenvolvimento](docs/development.md)**: assinaturas embutidas, traduções, testes e o pacote de release.
- **[facheiro.space.fast](https://facheiro.space.fast/)**: a página do projeto, em português, com o inglês em `/en/` (o código fica em `site/`).

## Requisitos

- WordPress 6.0+ e PHP 7.2+ para o plugin; a CLI independente e o modo de recuperação rodam em PHP 5.6+
- Acesso ao shell (WP-CLI ou `php`) para limpar ou restaurar arquivos; as páginas do painel não precisam de shell
- WordPress 6.9+ e o plugin [MCP Adapter](https://github.com/WordPress/mcp-adapter) para as ferramentas de assistentes de IA
- Apache ou LiteSpeed com `AllowOverride` para as regras de blindagem que o próprio Facheiro grava; no Nginx, você inclui o arquivo gerado na configuração do servidor

Alguns scanners usam extensões do PHP (zlib, curl, zip, mysqli) ou o `shell_exec`; a falta de uma delas aparece como um achado `ERROR`, em vez de a verificação ser pulada. A [referência](https://facheiro.space.fast/referencia/#php-extensions) diz qual scanner precisa de qual.

## Instalação

O Facheiro ainda não está no WordPress.org. Instale a partir deste repositório; a pasta precisa se chamar `facheiro`:

```
cd wp-content/plugins
git clone https://github.com/fcavallari/Facheiro.git facheiro
wp plugin activate facheiro
```

(ou baixe o repositório como zip, descompacte em `wp-content/plugins/facheiro/` e ative na tela de Plugins).

## Primeiros passos

1. **Facheiro (menu do painel) → Iniciar varredura.** A varredura roda em segundo plano pelo WP-Cron e não altera nada no site. Os achados aparecem do mais grave ao mais leve.
2. **Revise os achados**: marque os falsos positivos, baixe amostras para análise e exporte o relatório (veja [o plugin e o WP-CLI](https://github.com/fcavallari/Facheiro/wiki/Plugin-e-WP-CLI)).
3. **Aja sobre os resultados pelo WP-CLI**, depois de fazer um backup:

```
wp facheiro scan --dryrun                        # simula a limpeza por assinaturas
wp facheiro scan                                 # remove malware conhecido dos arquivos infectados
wp facheiro integrity --restore --dryrun         # simula a restauração de arquivos alterados/ausentes do core, plugins e temas
wp facheiro integrity --restore --quarantine-dir=/path/outside/webroot
```

Se o site não carrega mais, use o [modo de recuperação](https://github.com/fcavallari/Facheiro/wiki/Modo-de-recuperação) ou a [CLI independente](https://github.com/fcavallari/Facheiro/wiki/CLI-independente):

```
php bin/facheiro.php scanall=1 scandirectory=/path/to/wp-root   # todos os scanners, só relatório
php bin/facheiro.php dryrun=1 scandirectory=/path/to/site        # simula a limpeza por assinaturas, não grava nada
```

Na CLI independente a limpeza por assinaturas é o modo padrão: sem nenhuma opção de modo o script modifica arquivos, e `dryrun=1` é a chave que o torna só de relatório. **Sempre faça um backup antes de limpar.**

Uma varredura limpa não prova que o site está limpo: o Facheiro encontra e remove malware *conhecido* e relata os formatos comuns de backdoor. Veja as [limitações](https://github.com/fcavallari/Facheiro/wiki/Limitações).

## Licença

GPLv2 ou posterior. Veja `LICENSE`.
