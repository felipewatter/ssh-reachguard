# Política de Segurança

Versão 1.0.0 — projeto de engenharia e estudo. **Não há promessa de conformidade total com OpenSSH, nem auditoria independente.**

## Como reportar uma vulnerabilidade

Não publique detalhes técnicos exploráveis ou dados sensíveis em issues públicas antes de uma triagem. Utilize o recurso **Report a vulnerability** na aba **Security** do GitHub, se habilitado pelo mantenedor, ou entre em contato privadamente pelo perfil do mantenedor. Não forneça chaves privadas, inventários reais, endereços internos ou credenciais.

## Versões suportadas

A série 1.0.x recebe correções conforme disponibilidade do mantenedor. Versões anteriores não são mantidas.

## Escopo de confiança

Offline por design. Entradas JSON locais são tratadas como não confiáveis. A ferramenta não autentica operadores, não valida SSH real e não deve ser usada como fonte única para concessão/revogação de privilégios em infraestrutura de produção. Confira docs/THREAT_MODEL.md.

## Práticas para contribuição

Adicione testes de regressão para problemas reportados, especialmente parsing, operação com symlinks, limites de tamanho, serialização e identificação estável de findings. Jamais versionar segredos, chaves privadas ou snapshots reais.
