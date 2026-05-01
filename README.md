# zoo-indexer

`zoo-indexer` e uma ferramenta CLI em Python para indexar e consultar metadados de um checkout local do [theZoo](https://github.com/ytisf/theZoo).

Ela **nao abre, extrai ou executa malware**. A indexacao trabalha apenas com nomes de pastas, caminhos, arquivos de hash (`md5`, `sha256`) e digest dos arquivos compactados quando necessario.

## Estrutura

```text
zoo-indexer/
  main.py
  indexer.py
  search.py
  db.py
  utils.py
  requirements.txt
  scripts/
    zoo-indexer
    index-example.sh
  README.md
```

## Requisitos

- Python 3.10+
- SQLite, via biblioteca padrao do Python
- Bash apenas para os scripts auxiliares

Nao ha dependencias externas.

## Instalar

```bash
cd zoo-indexer
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
chmod +x scripts/zoo-indexer scripts/index-example.sh
```

Opcionalmente, adicione o script ao `PATH`:

```bash
export PATH="$PWD/scripts:$PATH"
```

## Uso

### Indexar um checkout local do theZoo

```bash
python3 main.py index /caminho/do/theZoo
```

Ou, usando o script auxiliar:

```bash
scripts/zoo-indexer index /caminho/do/theZoo
```

O indexador percorre:

- `malware/Binaries/`
- usa `malware/Source/` apenas como pista de metadados, quando existir

### Buscar por nome

```bash
python3 main.py search --name wannacry
```

### Busca aproximada

```bash
python3 main.py search --name wanacry --fuzzy
```

### Buscar por tipo

```bash
python3 main.py search --type ransomware
```

### Buscar por plataforma

```bash
python3 main.py search --platform windows
```

### Buscar por tags

```bash
python3 main.py search --tag ransomware --tag windows
```

### Listar registros

```bash
python3 main.py list
python3 main.py list --limit 25
```

### Saida JSON

```bash
python3 main.py search --type trojan --json
python3 main.py list --json
```

### Banco customizado

```bash
python3 main.py --db ./indices/thezoo.sqlite3 index /caminho/do/theZoo
python3 main.py --db ./indices/thezoo.sqlite3 search --platform windows
```

## Campos indexados

A tabela SQLite `malware` contem:

- `id`
- `name`
- `path`
- `type`
- `platform`
- `architecture`
- `md5`
- `sha256`
- `tags`

O campo `path` e unico, entao reindexar o mesmo diretorio atualiza os metadados sem duplicar registros.

## Inferencia

O tipo, plataforma, arquitetura e tags sao inferidos por palavras-chave presentes no nome, caminho ou arquivo compactado. Exemplos:

- `ransom`, `wannacry`, `locker` -> `ransomware`
- `trojan`, `rat`, `backdoor` -> `trojan`
- `worm`, `conficker`, `stuxnet` -> `worm`
- `win32`, `win64`, `.exe` -> `windows`
- `linux`, `elf` -> `linux`

Quando nao ha pista suficiente, o valor fica como `unknown`.

## Seguranca

Esta ferramenta foi desenhada para consulta defensiva de metadados:

- nao executa arquivos
- nao descompacta arquivos
- nao carrega binarios em memoria alem da leitura sequencial para hash
- nao chama ferramentas externas sobre amostras

Mesmo assim, mantenha o theZoo em um ambiente isolado e trate todo arquivo como hostil.
