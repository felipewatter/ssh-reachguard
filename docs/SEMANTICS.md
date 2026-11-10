# Semântica do modelo de autorização

## Chave de proprietário vs. autorização de conta

Cada `owner` possui uma ou mais chaves públicas **sem opções de authorized_keys**. Uma conta de host aceita linhas independentes de `authorized_keys` que incluem o mesmo material público (portanto o mesmo fingerprint), possivelmente com restrições. Um `owner` desativado é sempre negado pelo simulador, independentemente de a chave continuar instalada; o achado `SRG010` evidencia essa divergência.

Não há resolução de usernames do sistema, grupos, DNS, SSH CA ou identidade humana real. Dois owners podem atribuir o mesmo fingerprint; o modelo permite consultas independentes mas sinaliza o compartilhamento (SRG009). O fingerprint é calculado a partir dos bytes da representação SSH binária, não do texto base64 nem do comentário.

## Chaves aceitas

- `ssh-ed25519`: 32 bytes de material público (somente forma estrutural).
- `sk-ssh-ed25519@openssh.com`: chave 32 bytes e campo de aplicação que começa por `ssh:` (forma estrutural).
- `ssh-rsa`: campos SSH `e` e `n`, expoente ímpar maior ou igual a 3, n ímpar de 2048 a 16384 bits. A designação `ssh-rsa` de **tipo de chave** não prova que a autenticação real negociaria assinatura SHA-1; esta versão não simula algoritmos de assinatura.
- `ecdsa-sha2-nistp256`, `nistp384`, `nistp521`: curva e comprimento de ponto público sem compressão consistentes; não executa verificação matemática do ponto EC.

Não suporta SSH certificates, `cert-authority`, `principals=` e outros tipos não listados. A ausência de suporte é erro 2, não acesso permitido.

## Opções reconhecidas

| Opção OpenSSH | Semântica local |
|---|---|
| `restrict` | Desabilita PTY, port/agent/X11 forwarding e user-rc; opções positivas subsequentes podem reabilitar capacidades no **modelo** |
| `pty`, `no-pty` | Reabilita/bloqueia PTY; combinação contraditória rejeitada |
| `port-forwarding`, `no-port-forwarding` | Reabilita/bloqueia port forwarding |
| `agent-forwarding`, `no-agent-forwarding` | Reabilita/bloqueia encaminhamento de agente |
| `X11-forwarding`, `no-X11-forwarding` | Reabilita/bloqueia encaminhamento X11 |
| `user-rc`, `no-user-rc` | Reabilita/bloqueia `~/.ssh/rc`, apenas para postura (não faz parte dos seis modos avaliáveis) |
| `command="..."` | Marca a autorização como comando forçado, de modo que `mode=shell` é negado; **não** desabilita automaticamente forwarding |
| `from="IP,CIDR,!IP"` | Origem deve coincidir com ao menos uma rede positiva e nenhuma exclusão; IPv4/IPv6, somente IP/CIDR numéricos |
| `expiry-time="YYYYMMDDHHMMSSZ"` | Expiração UTC no segundo indicado, inclusiva: acesso negado se `at >= expiry` |

**Não implementados:** glob DNS/hostname em `from=`, revogações de SSH KRL, `permitopen`, `permitlisten`, `tunnel`, `environment`, `no-touch-required`, `verify-required`, `AuthorizedKeysCommand`, métodos de autenticação, controles de certificado, limites de encaminhamento por host/porta, opções e precedência de `sshd_config`. O parser rejeita tais opções em vez de interpretá-las incorretamente.

A combinação `from` usa o IP fornecido pelo operador; nunca faz resolução DNS. O resultado é independente de dados externos.

## Seis consultas suportadas

- `authenticate`: key autorizada para owner ativo e IP/tempo correspondente (não prova login efetivo).
- `shell`: como authenticate, exceto chave com `command=` (não representa execução de outro comando permitido).
- `pty`: como authenticate e `pty` permitido.
- `tcp-forward`: como authenticate e `port-forwarding` permitido.
- `agent-forward`: como authenticate e `agent-forwarding` permitido.
- `x11-forward`: como authenticate e `X11-forwarding` permitido.

**Escolha de escopo importante:** `authenticate` significa elegibilidade **do modelo de chave**, não o resultado de uma autenticação SSH. Uma chave que se encontra em dois registros pode conceder uma capacidade em um e negá-la no outro; o resultado é `allowed_in_model: true` se houver **pelo menos uma** entrada aplicável que a permita.

## Delimitação de regressão

`compare` testa exclusivamente o conjunto finito de queries JSON. Não demonstra equivalência universal de todas as combinações de hosts, IPs, contas e modos. Adicione um conjunto negativo de IPs externos, contas sensíveis, tipos de sessão e owners desativados representativo do contrato desejado. O gate bloqueia qualquer transição `false → true` presente na matriz, mesmo quando achados são tolerados por `--fail-on none`.

## Fontes de semântica

[OpenSSH sshd(8)](https://man.openbsd.org/sshd) e [ssh-keygen(1)](https://man.openbsd.org/ssh-keygen). Esta ferramenta usa **subconjunto próprio** e não promete paridade completa com a configuração real do OpenSSH.
