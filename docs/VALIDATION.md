# Evidências de validação

## Comandos locais

```bash
python -m unittest discover -s tests -v
python -m compileall -q src tests scripts
python scripts/package.py
python -m ssh_reachguard audit --fleet examples/baseline.json --at 2026-11-10T12:00:00Z
python -m ssh_reachguard assert --fleet examples/baseline.json --queries examples/queries.json --at 2026-11-10T12:00:00Z
python -m ssh_reachguard compare --baseline examples/baseline.json --candidate examples/candidate-risky.json --queries examples/queries.json --at 2026-11-10T12:00:00Z
```

Observações: o último comando **deve** retornar 1, pois foram identificadas duas regressões de acesso, e não por erro de execução. A auditoria do baseline deve retornar 0.

## Cobertura de comportamento

- Parsing de chaves SSH (Ed25519, RSA e ECDSA por forma binária), SHA-256, opções restritivas, escopo IP/CIDR, datas UTC, negação por expiradas e inválidas.
- Entitlements por proprietário e host/conta, matriz de acesso, duplicatas, owners desativados, blast radius, gates e diferentes modos de sessão.
- Exportação JSON/SARIF, overwrite negado, symlinks negados, JSON duplicado, grandes entradas, valores NaN e erros de CLI.
- Teste de mutação com PRNG fixo aplicando 1.200 alterações de uma linha e confirmando que o parser não lança erro inesperado.
- Repetição do empacotamento e confirmação de ZIP byte a byte idêntico, segurança de conteúdo e manifesto SHA-256.

A documentação do número de testes executados só deve ser atualizada após repetição do comando e leitura de seu resultado. O badge de CI não é evidência de sucesso remoto antes de uma execução real no GitHub Actions.

## Pipeline GitHub Actions

A matriz executa Python 3.11 e 3.13 em Ubuntu/Windows, instala o projeto, executa testes, valida compilação, confirma o baseline, valida asserções e exige que o candidato inseguro seja bloqueado. O job `release` depende de toda a matriz e somente publica `v1.0.0` com os arquivos ZIP e `.sha256`.

## Limitação de cobertura

Os testes não demonstram conformidade universal com a semântica de `sshd(8)`, segurança criptográfica, qualidade dos inventários fornecidos nem robustez a inputs ilimitados. A ferramenta não foi auditada por terceiros. O teste adversarial não equivale a fuzzing com cobertura e sanitizers.
