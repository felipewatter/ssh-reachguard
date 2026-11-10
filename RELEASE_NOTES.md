# SSH ReachGuard v1.0.0 — First public release

## Destaques

- Auditoria offline e conservadora de chaves públicas OpenSSH `authorized_keys` em snapshots declarativos.
- Mapeamento de `owner` → fingerprint SHA-256 → host → conta, com análise de permissões e riscos.
- Explicação de seis tipos de tentativa de sessão/encaminhamento; suporte a restrições IP/CIDR, comando forçado, expiração UTC e opções de forwarding.
- 12 sinais de risco operacional com identificadores estáveis, JSON e SARIF 2.1.0.
- Gate de comparação de alterações: um novo acesso explicitamente coberto pela matriz bloqueia o pipeline.
- Biblioteca padrão Python 3.11+ em runtime; documentação PT-BR e inglês.

## Validação

CI multiplataforma (Ubuntu e Windows, Python 3.11 e 3.13), testes automatizados, smoke tests e empacotamento reproduzível. A aprovação efetiva do CI deve ser verificada na aba Actions da publicação.

## Arquivos disponibilizados

- `ssh-reachguard-v1.0.0-source.zip`: código completo, testes, exemplos, workflows e documentação.
- `ssh-reachguard-v1.0.0-source.zip.sha256`: checksum para conferência da integridade.

## Restrições importantes

Não acessa servidores e não equivale a `sshd -T` nem a uma autenticação real. Não simula CA SSH, DNS em `from=`, `sshd_config`, certificados, revogações ou políticas externas. Não inclua inventários reais em repositórios públicos.
