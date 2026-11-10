# Modelo de ameaças — STRIDE simplificado

## Ativos e fronteiras de confiança

**Ativos:** inventário de owners, dados de servidores/contas, material de chaves **públicas**, fingerprints, achados e matriz de autorização. A raiz de confiança é um JSON explicitamente fornecido pelo operador/CI. Não existe rede, credencial remota ou coleta live.

| Vetor | Ameaça | Controle implementado | Risco residual |
|---|---|---|---|
| Spoofing | Inventário atribui mesma chave a outro owner | Identificação por fingerprint + SRG009 | Não comprova identidade humana nem posse de chave privada |
| Tampering | JSON malicioso, duplicação de campos e arrays gigantes | Leitura limitada a 2 MB, campos esperados, limites de coleções, rejeição de duplicatas | Operador pode fornecer um snapshot incompleto ou falsificado |
| Repudiation | Mudança de acesso sem registro | IDs estáveis, deltas e matrizes reproduzíveis, SARIF/JSON | Não cria log imutável nem assina evidências |
| Information disclosure | Relatório divulga detalhes operacionais | Não emite base64 da chave, comentário ou comando forçado; saída exclusiva com modo 0600 | Fingerprints/hostnames/account names ainda podem ser sensíveis |
| Denial of service | Base64 malformado, key blobs e JSON profundamente aninhado | Limites de input, limites SSH string, parser estrito, teste de mutações | Muitas queries × muitas chaves têm custo quadrático sob limites máximos |
| Elevation of privilege | Regras novas concedem acesso indevido | Regras de postura, `compare` e bloqueio de qualquer acesso introduzido na matriz | Matrizes não exaustivas deixam caminhos não testados; `sshd` real não é avaliado |
| Path injection | Input/relatório com links simbólicos | Rejeição de symlinks, O_NOFOLLOW quando disponível, criação exclusiva sem sobrescrita | Em Windows e ambientes sujeitos a corrida, validação não substitui isolamento do sistema de arquivos |
| Supply chain | Publicar código não testado ou artefato alterado | Workflow com actions pinadas por SHA, CI antes do release, ZIP determinístico e SHA-256 | Não há assinatura criptográfica de release por chave externa nem auditoria independente |

## Abusos explicitamente recusados

- Não executamos nem deserializamos código proveniente de `authorized_keys`; `command=` é **apenas interpretado como presença de comando**.
- Não tentamos SSH em hosts, descoberta, quebra de senhas/chaves, escalação, coleta de keys ou leitura de arquivos sensíveis.
- Não tomamos decisão sobre autenticação real: apenas avaliamos hipóteses declarativas.
- Opções e formatos desconhecidos falham com erro 2; jamais assumimos permissão a partir de sintaxe não suportada.

## Segurança operacional

Não versionar inventários reais ou chaves privadas. Executar CI com fixtures sintéticos. Para verificar configurações de produção, realizar revisão manual por engenheiro de segurança responsável e testes controlados de `sshd`, incluindo validação de regras externas e revogações.
