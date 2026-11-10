# Arquitetura — SSH ReachGuard 1.0.0

## Fluxo de dados

```text
fleet.json --- UTF-8 JSON estrito e limitado ---> Schema v1
                                                  |
                  Inventário owners/hosts/accounts|
                                                  v
       authorized_keys ---> lexer quoted-aware ---> SSH blob parser
                                                  |
                                   SHA-256 (bytes originais)
                                                  |
                            Motor de regras (SRG001–SRG012)
                                                  |
    Query (IP, modo, data) ---> Avaliador declarativo de acesso
                                                  |
    baseline + candidate + matriz --> diferenças e regressões
                                                  |
                             stdout / JSON / SARIF / exit code
```

**Módulos:** `parser.py`: léxico, base64, SSH wire-format e opções restritivas. `engine.py`: valida inventário, mapeia proprietários, audita, avalia queries e calcula deltas. `io.py`: I/O com limites e relatórios JSON/SARIF. `cli.py`: argumentos, severidade e códigos de saída. `scripts/package.py`: fonte determinística e checksum.

## Contratos

- JSON `schema: 1`; host `name`, `critical?`, `accounts[]`; account `name`, `authorized_keys[]`; owner `id`, `status?`, `keys[]`.
- Limites: 2 MB por documento, 150 hosts, 200 contas/host, 300 chaves/conta, 500 proprietários, 100 chaves/proprietário, 12.000 entradas autorizadas, até 1.000 queries.
- Chaves de JSON duplicadas, estruturas desconhecidas, tipos errados, datas inválidas e escapes não suportados resultam em **erro**, não inferência.
- Identificador de finding = primeiros 20 caracteres hex do SHA-256 de `regra:host:conta:fingerprint`. Muda apenas se esses campos mudam. Mensagens e metadados não entram na identidade.
- `compare` mantém findings novos/resolvidos por identidade, informa os persistentes como contagem e testa exatamente as queries fornecidas.
- Nenhum blob de chave nem comentário da linha original é emitido nos relatórios; metadados continuam sensíveis.

## Decisões arquiteturais

1. **Sem acesso SSH e sem DNS.** Permite revisão de change requests sem credenciais, scans e modificações do ambiente.
2. **Falha fechada na sintaxe desconhecida.** Em particular, não finge suportar SSH CA, padrões DNS, host patterns, directives de `sshd_config` nem todos os tipos de chave.
3. **Timestamp explícito em exemplos/CI.** Evita que resultados dependam do relógio local e dos efeitos do horário de verão.
4. **Duas famílias de evidências.** Findings de postura e testes de acesso modelado não são a mesma coisa. Um cenário pode ser aprovado na matriz e ter finding, ou o inverso.
5. **Sem estratégia de escrita em inventários.** O programa jamais altera o snapshot analisado. Os relatórios são criados exclusivamente e não sobrescritos.
6. **Sem dependências externas em runtime.** Reproduzível em ambientes corporativos com instalação de Python 3.11+.

## Desempenho e condições de exaustão

O motor percorre entradas e queries em memória. A análise comparativa possui custo aproximado `O(total_entries × total_queries)`, com limites explícitos de entrada. Esta versão não pretende processar milhões de entradas; ampliação de limites exige profiling e revisão de negação de serviço.

## Não objetivos

Não implementar servidor SSH, handshake, criptografia privada, autenticação real, inventário remoto, coleta automática ou alterações em `authorized_keys`. Não substituir OpenSSH `sshd -T`, `ssh-keygen` ou revisão de access control em infraestrutura real.
