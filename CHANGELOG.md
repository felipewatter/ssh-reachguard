# Histórico de versões

## 1.0.0 — 2026-11-10

- Inventário SSH offline com owners ativos/desativados, hosts, contas e authorized_keys.
- Parser de formato SSH com fingerprint SHA-256; validação estrutural para Ed25519, RSA, ECDSA e FIDO Ed25519.
- Subconjunto restrito e fail-closed de opções `authorized_keys`.
- Motor de avaliação de seis modos de autorização por IP e tempo.
- 12 regras de postura SRG001–SRG012, gatilhos de severidade, JSON, texto e SARIF.
- Comparação com matriz explícita e bloqueio de autorizações novas.
- Testes, CI, documentação PT-BR/EN, licença MIT, ZIP determinístico e SHA-256.

**Nota:** resultado `allowed_in_model` não equivale a acesso SSH confirmado.
