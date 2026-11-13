# Política de Uso Responsável e Segurança

O **Kit de Bolso do Técnico** é uma ferramenta de diagnóstico e auditoria
**defensiva**, para trabalho técnico e aprendizado em segurança da informação,
redes e hardware.

## Uso permitido
- Diagnóstico e inventário da **sua própria rede** e dos seus dispositivos.
- Auditoria de redes de terceiros **com autorização expressa e documentada**
  (laboratório didático, contrato de pentest).
- Estudo do funcionamento de protocolos e da própria ferramenta.

## Uso proibido
- Varrer, monitorar ou auditar redes e dispositivos sem autorização.
- Interceptar comunicações de terceiros.

## Escopo técnico
Esta ferramenta **não** contém módulos de ataque ativo (negação de serviço,
deauth de Wi-Fi, man-in-the-middle, captura de credenciais, spoofing de
ARP/DNS). Ela apenas **detecta** indícios desses ataques (rajada de deauth, ARP
spoofing, DHCP falso, tráfego inseguro), como parte da defesa.
As varreduras ativas (`nmap`, inventário) são restritas por código a faixas de
IP privadas.

## Modelo de segurança do servidor
- **Token** obrigatório em toda a API (`~/kit/.token`, permissão 600), via
  cabeçalho `X-Kit-Token` ou cookie `HttpOnly; SameSite=Strict`.
- Validação do cabeçalho `Host` (anti DNS rebinding).
- Ações que alteram estado exigem `POST`.
- Validação de alvos (rejeita opções de linha de comando e alvos públicos em
  varreduras ativas).
- Porta de captura (UDP 5123) restrita a `127.0.0.1`.
- Token comparado em tempo constante (`secrets.compare_digest`).
- Importação de `.pcap` exige token e `POST`, limitada a 25 MB, e só lê o
  arquivo (nada é executado).
- O inventário respeita exatamente a faixa pedida (até /24) e só IPv4 privado.
- O agendamento aceita só faixa privada e intervalo de 5 a 1440 minutos.
- Varreduras ativas (portas, roteador, UPnP, mDNS, inventário, nmap) só por
  `POST`.
- CSP sem `'unsafe-inline'` em scripts: o único `<script>` leva um nonce novo
  a cada carregamento e a interface não usa atributos `onclick`.
- Os arquivos do app instalável (manifest, service worker, ícones) são
  públicos porque não têm segredo; o service worker não guarda a página em
  cache (ela contém o token).
- **Agenda presa à rede:** a varredura agendada só roda na rede em que foi
  configurada. Em outra rede (café, cliente) ela pausa e registra "agenda
  pausada: rede diferente". Isso evita varrer, sem querer, uma rede alheia.
- **Redes separadas:** inventário, histórico e alertas são guardados por rede,
  então dados de um cliente não aparecem nem geram alerta em outro.
- **`--lan` não tem criptografia.** O tráfego é HTTP puro e o token pode ser
  capturado por quem estiver na mesma rede. Use só na sua rede e depois rode
  `kit --novo-token`, que invalida o token antigo.
- Detecções de deauth, ARP spoofing e DHCP falso dependem de `.pcap`
  importado: o PCAPdroid sem root só vê o tráfego do próprio aparelho.

## Responsabilidade
O uso é de inteira responsabilidade do usuário. Varredura e monitoramento não
autorizados de redes podem configurar crime (no Brasil, p. ex., a Lei
12.737/2012 e o Marco Civil da Internet).

## Reportar uma vulnerabilidade
Encontrou uma falha de segurança no próprio Kit? Abra uma *issue* no
repositório descrevendo o problema e os passos para reproduzir. Evite publicar
detalhes sensíveis antes de uma correção.
