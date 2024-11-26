# Intro-Analise-de-Log-THM-Walkthroug

TAREFA 2

Noções básicas de análise de log

Entre as várias fontes de dados coletadas e utilizadas por sistemas de infraestrutura, os logs são essenciais para oferecer insights valiosos sobre o funcionamento interno e as interações desses sistemas na rede. Um log é um fluxo de mensagens sequenciadas no tempo que registram eventos ocorridos. A análise de log é o processo de dar sentido aos eventos capturados nos logs para pintar uma imagem clara do que aconteceu na infraestrutura.
O que são logs?
Logs são eventos ou transações registrados dentro de um sistema, dispositivo ou aplicativo. Especificamente, esses eventos podem estar relacionados a erros de aplicativo, falhas do sistema, ações de usuário auditadas, usos de recursos, conexões de rede e muito mais. Cada entrada de log contém detalhes relevantes para contextualizar o evento, como seu registro de data e hora (a data e hora em que ocorreu), a fonte (o sistema que gerou o log) e informações adicionais sobre o evento de log específico.

![image](https://github.com/user-attachments/assets/0386875d-34c8-4a88-be30-046e1df13650)


No exemplo acima, esta entrada de log significa um evento detectado por um firewall sobre atividade de rede incomum de um sistema interno, indicando uma potencial preocupação de segurança. Os campos relevantes a serem considerados neste exemplo são:

Jul 28 17:45:02- Este registro de data e hora mostra a data e a hora do evento.

10.10.0.4- Isso se refere ao endereço IP do sistema (a origem) que gerou o log.

%WARNING%- Isso indica a gravidade do log, neste caso, Aviso . As entradas de log geralmente recebem um nível de gravidade para categorizar e comunicar sua importância ou impacto relativo. Esses níveis de gravidade ajudam a priorizar respostas, investigações e ações com base na criticidade dos eventos. Sistemas diferentes podem usar níveis de gravidade ligeiramente diferentes, mas, comumente, você pode esperar encontrar os seguintes níveis de gravidade crescentes: Informativo, Aviso, Erro e Crítico.
Action: Alert- Neste caso, a política do firewall foi configurada para notificar quando tal atividade incomum ocorre.
Os campos restantes nos dão informações específicas relacionadas ao evento registrado. Especificamente, essa atividade de rede incomum foi detectada do IP 10.10.0.15 ao IP 203.0.113.25.
Com base no Source Zonecampo, o tráfego parece destinado à Internet ( External ), e o Application foi categorizado como web-browsing .
Por que os logs são importantes?
Há várias razões pelas quais coletar logs e adotar uma estratégia de análise de log eficaz é vital para as operações contínuas de uma organização. Algumas das atividades mais comuns incluem:

•	Solução de problemas do sistema : analisar erros do sistema e logs de avisos ajuda as equipes de TI a entender e responder rapidamente a falhas do sistema, minimizando o tempo de inatividade e melhorando a confiabilidade geral do sistema.

•	Incidentes de segurança cibernética: No contexto de segurança, os logs são cruciais para detectar e responder a incidentes de segurança. Logs de firewall , logs de sistema de detecção de intrusão (IDS) e logs de autenticação do sistema, por exemplo, contêm informações vitais sobre ameaças potenciais e atividades suspeitas. A execução de análise de log ajuda as equipes do SOC e os analistas de segurança a identificar e responder rapidamente a tentativas de acesso não autorizado, malware, violações de dados e outras atividades maliciosas.

•	Threat Hunting: No lado proativo, as equipes de segurança cibernética podem usar logs coletados para pesquisar ativamente ameaças avançadas que podem ter escapado das medidas de segurança tradicionais. Analistas de segurança e Threat Hunters podem analisar logs para procurar padrões incomuns, anomalias e indicadores de comprometimento (IOCs) que podem indicar a presença de um agente de ameaça.

•	Conformidade: As organizações devem frequentemente manter registros detalhados das atividades de seus sistemas para fins regulatórios e de conformidade. A análise regular de logs garante que as organizações possam fornecer relatórios precisos e demonstrar conformidade com regulamentações como GDPR, HIPAA ou PCI DSS .

![image](https://github.com/user-attachments/assets/c8eaaf39-0a84-4ad5-aa3f-c73d21ed4165)

Conforme discutido na sala Introdução aos Logs  , diferentes componentes dentro de um ambiente de computação geram vários tipos de logs, cada um servindo a um propósito distinto. Esses tipos de log incluem, mas não estão limitados a:

•	Logs de aplicativos: mensagens de aplicativos específicos, fornecendo insights sobre seu status, erros, avisos e outros detalhes operacionais.

•	Logs de auditoria: eventos, ações e alterações que ocorrem em um sistema ou aplicativo, fornecendo um histórico das atividades do usuário e do comportamento do sistema.

•	Logs de segurança: eventos relacionados à segurança, como logins, alterações de permissão, atividades de firewall e outras ações que afetam a segurança do sistema.

•	Logs do servidor: logs do sistema, logs de eventos, logs de erros e logs de acesso, cada um oferecendo informações distintas sobre as operações do servidor.

•	Logs do sistema: atividades do kernel, erros do sistema, sequências de inicialização e status do hardware, auxiliando no diagnóstico de problemas do sistema.

•	Registros de rede: comunicação e atividade dentro de uma rede, capturando informações sobre eventos, conexões e transferências de dados.

•	Logs de banco de dados: atividades dentro de um sistema de banco de dados, como consultas realizadas, ações e atualizações.

•	Logs do servidor Web: solicitações processadas por servidores Web, incluindo URLs, endereços IP de origem, tipos de solicitação, códigos de resposta e muito mais.

Cada tipo de log apresenta uma perspectiva única sobre as atividades dentro de um ambiente, e analisar esses logs em contexto uns com os outros é crucial para uma investigação eficaz de segurança cibernética e detecção de ameaças.


![image](https://github.com/user-attachments/assets/801c81e9-350e-4628-8015-478e3e2ba6b1)

-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------


TAREFA 3

Teoria da Investigação





