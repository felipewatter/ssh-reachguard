# Catálogo de regras — SSH ReachGuard

Os sinais abaixo são **heurísticos** e não constituem prova de vulnerabilidade. A prioridade serve à triagem de controles de menor privilégio, não à classificação CVSS.

| ID | Nível | O que dispara | Possível ação operacional |
|---|---|---|---|
| SRG001 | Alto | Fingerprint de chave autorizada sem nenhum `owner` registrado | Confirmar responsável, avaliar remoção de chave desconhecida |
| SRG002 | Crítico | Entrada `root` sem `restrict`, `from`, `command` ou `expiry-time` | Restringir e revisar concessão privilegiada |
| SRG003 | Alto | Chave de `root` sem IP/CIDR positivo em `from` | Limitar faixa de origens de administração |
| SRG004 | Alto | Chave de `root` permite encaminhamento de portas | Aplicar `restrict` ou `no-port-forwarding` quando apropriado |
| SRG005 | Médio | Chave de `root` não tem comando forçado | Revisar necessidade de shell livre |
| SRG006 | Médio | Chave de `root` não tem expiração | Criar ciclo explícito de renovação |
| SRG007 | Alto | Chave em host marcado `critical: true` sem `from` numérico | Restringir origem de operações críticas |
| SRG008 | Médio | Chave tem `expiry-time` <= horário de avaliação | Remover material obsoleto de `authorized_keys` |
| SRG009 | Alto | Fingerprint mapeado para mais de um `owner` | Investigar compartilhamento e rotacionar chave |
| SRG010 | Alto | Fingerprint associado a proprietário `disabled` ainda está autorizado | Revogar na infraestrutura e confirmar sincronização |
| SRG011 | Médio | Fingerprint repetido em uma mesma conta/host | Consolidar entradas e divergências de restrições |
| SRG012 | Alto | Fingerprint consta em mais que `--max-hosts` hosts distintos | Reduzir blast radius ou justificar exceção |

## Identidade e estabilidade

O identificador é truncamento de SHA-256 do texto `rule:host:account:fingerprint`. Isso impede mudanças de severidade ou texto de criarem um finding distinto; porém restrições alteradas podem manter o mesmo finding ID quando a regra permanece disparada. A análise de acesso deve ser feita adicionalmente com a matriz de queries.

## Severidade e saída

`--fail-on high` bloqueia findings de severidade alta/crítica. `--fail-on medium` inclui médios. `--fail-on low` inclui todos os níveis acima. `--fail-on none` desabilita gate por findings, mas **não** desabilita rejeição de entradas inválidas e **não** libera autorização ampliada na matriz do `compare`.

## Política de exceções

Não há silenciamentos automáticos por nome de servidor ou chave. Para regras de alto risco que sejam intencionais, um change review deve registrar aprovação fora da ferramenta, preferencialmente com testes de acesso negativo que verifiquem as condições restantes. Esta versão não faz gerenciamento de exceções.
