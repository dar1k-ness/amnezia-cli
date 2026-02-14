# AmneziaCLI

CLI для локального управления пользователями AmneziaWG (Docker на текущем сервере).

## Установка

```bash
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

## Опции окружения

```bash
amz user add <username> --direct
amz user add <username> --awg-container amnezia-awg
amz user add <username> --wg-config-path /opt/amnezia/awg/awg0.conf
```

## Тесты

```bash
python3 -m unittest discover -s tests -v
```
