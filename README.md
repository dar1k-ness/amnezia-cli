# AmneziaCLI

CLI для управления пользователями AmneziaWG на сервере.

## Требования

- Python 3.8+
- pip3
- На сервере установлен AmneziaWG (self-hosted)

## Установка

```bash
git clone git@github.com:dar1k-ness/amnezia-cli.git && cd amnezia-cli
pip3 install .
amz --help
```

## Основные команды

```bash
amz user add <username>
amz user list
amz user show <username>
amz user del <username>
```

## Полезные флаги

```bash
amz user add <username> --out-token ./user.token.txt --out-config ./user.conf --json
amz user del <username> --public-key <PUBKEY>
amz user del <username> --dry-run
```

## Если автоопределение не сработало

```bash
amz user add <username> --wg-config-path /opt/amnezia/awg/wg0.conf
```

## Тесты

```bash
python3 -m unittest discover -s tests -v
```
