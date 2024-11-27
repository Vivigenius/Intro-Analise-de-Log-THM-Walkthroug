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


Linha do tempo

Ao conduzir análise de log, criar uma linha do tempo é um aspecto fundamental para entender a sequência de eventos dentro de sistemas, dispositivos e aplicativos. Em um alto nível, uma linha do tempo é uma representação cronológica dos eventos registrados, ordenados com base em sua ocorrência. A capacidade de visualizar uma linha do tempo é uma ferramenta poderosa para contextualizar e compreender os eventos que ocorreram em um período específico.

Em cenários de resposta a incidentes, os cronogramas desempenham um papel crucial na reconstrução de incidentes de segurança. Com um cronograma eficaz, os analistas de segurança podem rastrear a sequência de eventos que levam a um incidente, permitindo que eles identifiquem o ponto inicial de comprometimento e entendam as táticas, técnicas e procedimentos (TTPs) do invasor.


Carimbo de data/hora

Na maioria dos casos, os logs normalmente incluem carimbos de data/hora que registram quando um evento ocorreu. Com o potencial de muitos dispositivos, aplicativos e sistemas distribuídos gerando eventos de log individuais em várias regiões, é crucial considerar o fuso horário e o formato de cada log. A conversão de carimbos de data/hora para um fuso horário consistente é necessária para análise precisa de log e correlação entre diferentes fontes de log.
Muitas soluções de monitoramento de log resolvem esse problema por meio da detecção de fuso horário e configuração automática. O Splunk , por exemplo, detecta e processa automaticamente fusos horários quando os dados são indexados e pesquisados. Independentemente de como o tempo é especificado em eventos de log individuais, os timestamps são convertidos para o horário UNIX e armazenados no _timecampo quando indexados.

Esse timestamp consistente pode então ser convertido para um fuso horário local durante a visualização, o que torna os relatórios e análises mais eficientes. Essa estratégia garante que os analistas possam conduzir investigações precisas e obter insights valiosos de seus dados de log sem intervenção manual.


Super Linhas do Tempo

Uma super linha do tempo, também conhecida como linha do tempo consolidada, é um conceito poderoso em análise de log e forense digital. Super linhas do tempo fornecem uma visão abrangente de eventos em diferentes sistemas, dispositivos e aplicativos, permitindo que analistas entendam a sequência de eventos de forma holística. Isso é particularmente útil para investigar incidentes de segurança envolvendo vários componentes ou sistemas.

Super timelines geralmente incluem dados de fontes de log discutidas anteriormente, como logs de sistema, logs de aplicativo, logs de tráfego de rede, logs de firewall e muito mais. Ao combinar essas fontes díspares em uma única timeline, os analistas podem identificar correlações e padrões que precisam ser aparentes ao analisar logs individualmente.

Criar uma linha do tempo consolidada com todas essas informações manualmente levaria tempo e esforço. Você não só teria que registrar carimbos de data/hora para cada arquivo no sistema, mas também precisaria entender os métodos de armazenamento de dados de cada aplicativo. Felizmente, o Plaso (Python Log2Timeline) é uma ferramenta de código aberto criada por Kristinn Gudjonsson e muitos colaboradores que automatiza a criação de linhas do tempo de várias fontes de log. Ele foi projetado especificamente para análise forense digital e de log e pode analisar e processar dados de log de uma ampla gama de fontes para criar uma linha do tempo unificada e cronológica.
Para saber mais sobre o Plaso e seus recursos, visite a página de documentação oficial aqui .


Visualização de dados

Ferramentas de visualização de dados, como Kibana (do Elastic Stack) e Splunk, ajudam a converter dados de log brutos em representações visuais interativas e perspicazes por meio de uma interface de usuário. Ferramentas como essas permitem que analistas de segurança entendam os dados indexados visualizando padrões e anomalias, geralmente em uma visualização gráfica. Várias visualizações, métricas e elementos gráficos podem ser construídos em uma visualização de painel personalizada, permitindo uma visualização abrangente de "painel único" para operações de análise de log.
![image](https://github.com/user-attachments/assets/e803ac96-5962-4468-8e3e-e321e28d6e03)


Para criar visualizações de log eficazes, é essencial primeiro entender os dados (e fontes) que estão sendo coletados e definir objetivos claros para a visualização.

Por exemplo, suponha que o objetivo seja monitorar e detectar padrões de aumento de tentativas de login com falha. Nesse caso, devemos procurar visualizar logs que auditam tentativas de login de um servidor de autenticação ou dispositivo de usuário. Uma boa solução seria criar um gráfico de linhas que exibe a tendência de tentativas de login com falha ao longo do tempo. Para gerenciar a densidade de dados capturados, podemos filtrar a visualização para mostrar os últimos sete dias. Isso nos daria um bom ponto de partida para visualizar o aumento de tentativas com falha e detectar anomalias.


Monitoramento e alerta de log

Além da visualização, a implementação de monitoramento e alertas de log eficazes permite que as equipes de segurança identifiquem ameaças proativamente e respondam imediatamente quando um alerta é gerado.
Muitas soluções SIEM (como Splunk e Elastic Stack) permitem a criação de alertas personalizados com base em métricas obtidas em eventos de log. Eventos que valem a pena criar alertas podem incluir várias tentativas de login com falha, escalonamento de privilégios, acesso a arquivos confidenciais ou outros indicadores de possíveis violações de segurança. Os alertas garantem que as equipes de segurança sejam prontamente notificadas sobre atividades suspeitas que exigem atenção imediata.

Funções e responsabilidades devem ser definidas para procedimentos de escalonamento e notificação durante vários estágios do processo de resposta a incidentes. Procedimentos de escalonamento garantem que os incidentes sejam abordados prontamente e que o pessoal certo seja informado em cada nível de gravidade.

Para um tutorial prático sobre painéis e alertas no Splunk, é recomendável conferir a sala Splunk : Painéis e relatórios !


Pesquisa externa e inteligência sobre ameaças

Identificar o que pode ser de interesse para nós na análise de log é essencial. É desafiador analisar um log se não temos certeza do que estamos procurando.
Primeiro, vamos entender o que é inteligência de ameaça. Em resumo, inteligência de ameaça são pedaços de informação que podem ser atribuídos a um ator malicioso. Exemplos de inteligência de ameaça incluem:

•	Endereços IP

•	Hashes de arquivo

•	Domínios

Ao analisar um arquivo de log, podemos procurar pela presença de inteligência de ameaças. Por exemplo, veja esta entrada do servidor web Apache2 abaixo. Podemos ver que um endereço IP tentou acessar o painel de administração do nosso site.
![image](https://github.com/user-attachments/assets/3e0690c9-0a1d-4d3d-9eee-18acc74589ba)
Usando um feed de inteligência de ameaças como o ThreatFox , podemos pesquisar em nossos arquivos de log a presença de agentes maliciosos conhecidos.

![image](https://github.com/user-attachments/assets/962f56ad-84be-4252-8a60-6b5f2cb69ad0)
![image](https://github.com/user-attachments/assets/2b88cca0-e9cc-4720-897a-91ee98c5d410)

RESPOSTAS DA TAREFA 3
![image](https://github.com/user-attachments/assets/1ba86877-52dc-4f61-9fa9-d02337f19663)
EXPLICAÇÃO: Super Timelines se refere a uma linha do tempo consolidada que mostra os eventos de diversos dispositivos, sistemas e aplicativos. Sendo útil pra fornecer uma visão abrangente dos eventos em diferentes sistemas durante uma investigação de segurança.

![image](https://github.com/user-attachments/assets/18137e42-5ce4-4b1e-88a2-642a476ae90c)
EXPLICAÇÃO: Os valores são hashes de arquivos podem ser usados para comparar com uma base de dados de ameaças conhecidas. Se um hash de um arquivo corresponder a um hash de uma lista de malware, isso pode indicar que o arquivo é malicioso. Portanto, um file hash é um indicador essencial na inteligência de ameaças e em investigações de segurança, ajudando a correlacionar evidências e identificar comportamentos maliciosos de maneira precisa.

------------------------------------------------------------------------------------------------------------------------------------------------------------------------------


TAREFA 4 


Engenharia de Detecção


Locais comuns de arquivos de log

Um aspecto crucial da análise de log é entender onde localizar os arquivos de log gerados por vários aplicativos e sistemas. Embora os caminhos dos arquivos de log possam variar devido às configurações do sistema, versões de software e configurações personalizadas, conhecer os locais comuns dos arquivos de log é essencial para uma investigação eficiente e detecção de ameaças.

•	Servidores Web:

•	Nginx:

•	Registros de acesso:/var/log/nginx/access.log

•	Registros de erros:/var/log/nginx/error.log

•	Apache :

•	Registros de acesso:/var/log/apache2/access.log

•	Registros de erros:/var/log/apache2/error.log

•	Bases de dados:

•	MySQL:

•	Registros de erros:/var/log/mysql/error.log

•	PostgreSQL:

•	Registros de erros e atividades:/var/log/postgresql/postgresql-{version}-main.log

•	Aplicações Web:

•	PHP :

•	Registros de erros:/var/log/php/error.log

•	Sistemas operacionais:

•	Linux :

•	Logs gerais do sistema:/var/log/syslog

•	Registros de autenticação:/var/log/auth.log

•	Firewalls e IDS/ IPS :

•	iptables:

•	Registros de firewall :/var/log/iptables.log

•	Snort:

•	Registros do Snort:/var/log/snort/


Embora esses sejam caminhos comuns de arquivo de log, é importante observar que os caminhos reais podem diferir com base nas configurações do sistema, versões de software e configurações personalizadas. É recomendável consultar a documentação oficial ou os arquivos de configuração para verificar os caminhos corretos do arquivo de log para garantir análise e investigação precisas.


Padrões comuns

Em um contexto de segurança, reconhecer padrões e tendências comuns em dados de log é crucial para identificar potenciais ameaças à segurança. Esses "padrões" se referem aos artefatos identificáveis deixados para trás em logs por agentes de ameaças ou incidentes de segurança cibernética. Felizmente, existem alguns padrões comuns que, se aprendidos, melhorarão suas habilidades de detecção e permitirão que você responda eficientemente a incidentes.


Comportamento anormal do usuário

Um dos padrões primários que podem ser identificados está relacionado ao comportamento incomum ou anômalo do usuário. Isso se refere a quaisquer ações ou atividades conduzidas por usuários que se desviem de seu comportamento típico ou esperado.

Para detectar efetivamente o comportamento anômalo do usuário, as organizações podem empregar soluções de análise de log que incorporam mecanismos de detecção e algoritmos de aprendizado de máquina para estabelecer padrões de comportamento normais. Desvios desses padrões ou linhas de base podem então ser alertados como potenciais incidentes de segurança. Alguns exemplos dessas soluções incluem Splunk User Behavior Analytics ( UBA ), IBM QRadar UBA e Azure AD Identity Protection .

Os indicadores específicos podem variar muito dependendo da fonte, mas alguns exemplos que podem ser encontrados em arquivos de log incluem:

•	Várias tentativas de login com falha

•	Um número anormalmente alto de logins com falha em um curto período de tempo pode indicar um ataque de força bruta.

•	Tempos de login incomuns

•	Eventos de login fora dos horários ou padrões de acesso típicos do usuário podem indicar acesso não autorizado ou contas comprometidas.

•	Anomalias geográficas

•	Eventos de login de endereços IP em países que o usuário normalmente não acessa podem indicar possível comprometimento da conta ou atividade suspeita.

•	Além disso, logins simultâneos de diferentes localizações geográficas (ou indicações de viagem impossível) podem sugerir compartilhamento de conta ou acesso não autorizado.

•	Mudanças frequentes de senha

•	Eventos de log que indicam que a senha de um usuário foi alterada com frequência em um curto período podem sugerir uma tentativa de ocultar acesso não autorizado ou assumir o controle de uma conta.

•	Sequências de caracteres de agente de usuário incomuns

•	No contexto de logs de tráfego HTTP , solicitações de usuários com sequências de agentes de usuário incomuns que diferem de seus navegadores típicos podem indicar ataques automatizados ou atividades maliciosas.

•	Por exemplo, por padrão, o scanner Nmap registrará um agente de usuário contendo "Nmap Scripting Engine". A ferramenta de força bruta Hydra , por padrão, incluirá "(Hydra)" em seu agente de usuário. Esses indicadores podem ser úteis em arquivos de log para detectar atividade maliciosa em potencial.

A importância dessas anomalias pode variar muito dependendo do contexto específico e dos sistemas implementados, por isso é essencial ajustar quaisquer mecanismos automatizados de detecção de anomalias para minimizar falsos positivos.


Assinaturas de Ataque Comuns

Identificar assinaturas de ataque comuns em dados de log é uma maneira eficaz de detectar e responder rapidamente a ameaças. As assinaturas de ataque contêm padrões ou características específicas deixadas para trás por agentes de ameaças. Elas podem incluir infecções por malware, ataques baseados na web ( injeção de SQL , script entre sites, travessia de diretório) e muito mais. Como isso depende inteiramente da superfície de ataque, alguns exemplos de alto nível incluem:


Injeção de SQL

A injeção de SQL tenta explorar vulnerabilidades em aplicativos da web que interagem com bancos de dados. Procure por consultas SQL incomuns ou malformadas nos logs do aplicativo ou do banco de dados para identificar padrões comuns de ataque de injeção de SQL .

Consultas SQL suspeitas podem conter caracteres inesperados, como aspas simples ( '), comentários ( --, #), instruções union ( UNION) ou ataques baseados em tempo ( WAITFOR DELAY, SLEEP()). Uma lista útil de payload SQLi para referência pode ser encontrada aqui .

No exemplo abaixo, uma tentativa de injeção de SQL pode ser identificada pela ' UNION SELECTseção do q=parâmetro de consulta. O invasor parece ter escapado da consulta SQL com aspas simples e injetado uma instrução union select para recuperar informações da userstabela no banco de dados. Frequentemente, essa carga útil pode ser codificada por URL, exigindo uma etapa de processamento adicional para identificá-la de forma eficiente.

![image](https://github.com/user-attachments/assets/430e047e-a88f-41d6-b620-e34c2cb94a6f)


Script entre sites ( XSS )


Explorar vulnerabilidades de script entre sites ( XSS ) permite que invasores injetem scripts maliciosos em páginas da web. Para identificar padrões comuns de ataque XSS , geralmente é útil procurar entradas de log com entrada inesperada ou incomum que incluam tags de script ( <script>) e manipuladores de eventos ( onmouseover, onclick, onerror). Uma lista de payload XSS útil para referência pode ser encontrada aqui .


No exemplo  abaixo , uma tentativa de script entre sites pode ser identificada pela <script>alert(1);</script>carga inserida no searchparâmetro, que é um método de teste comum para vulnerabilidades XSS .

![image](https://github.com/user-attachments/assets/81d0185c-8d98-4c1f-9a0c-f85fa0773e6e)



Travessia de caminho

Explorar vulnerabilidades de travessia de caminho permite que invasores acessem arquivos e diretórios fora da estrutura de diretório pretendida de um aplicativo da web, levando a acesso não autorizado a arquivos ou códigos confidenciais. Para identificar padrões comuns de ataque de travessia, procure por caracteres de sequência de travessia ( ../e ../../) e indicações de acesso a arquivos confidenciais ( /etc/passwd, /etc/shadow). Uma lista útil de payload de travessia de diretório para referência pode ser encontrada aqui .

É importante notar, como nos exemplos acima, que as travessias de diretórios são frequentemente codificadas em URL (ou codificadas em URL dupla) para evitar a detecção por firewalls ou ferramentas de monitoramento. Por isso, %2Ee %2Fsão caracteres codificados em URL úteis para saber, pois se referem a .e /respectivamente.

No exemplo abaixo, uma tentativa de travessia de diretório pode ser identificada pela sequência repetida de ../caracteres, indicando que o invasor está tentando "sair" do diretório da web e acessar o /etc/passwdarquivo confidencial no servidor.

![image](https://github.com/user-attachments/assets/f0f6ad05-4016-4ffd-a9cc-0841c1338499)


RESPOSTAS DA TAREFA 4
![image](https://github.com/user-attachments/assets/6d0b3c6e-ff39-41ef-a016-3a48e9809469)
EXPLICAÇÃO: /var/log/nginx/access.log é o caminho padrão onde os logs de acesso do Nginx são armazenados no Linux. Esses logs contêm registros das solicitações HTTP feitas ao servidor, sendo também informações sobre clientes que acessaram o site, os recursos solicitados, entre outros dados. Esses logs são para monitorar o desempenho, identificar problemas e detectar acessos maliciosos.


![image](https://github.com/user-attachments/assets/5abceac6-a8c9-4499-a4a5-8a0e23492efa)
Path Traversal uma vulnerabilidade onde o invasor tenta acessar arquivos e diretórios que estão fora da estrutura do diretório pretendida pela aplicação web. O objetivo do ainvasor é usar comandos como %2E%2E%2F (equivalente a ../ codificado em URL) pra subir a árvore de diretórios e acessar informações sensíveis no sistema. Nesse caso específico da pergunta da tarefa, ele está tentando acessar o arquivo /proc/self/environ, que pode conter variáveis do ambiente, incluindo informações sensíveis.



------------------------------------------------------------------------------------------------------------------------------------------------------------------------------



TAREFA 5

Análise automatizada vs Manual


Análise automatizada:
A análise automatizada envolve o uso de ferramentas. Por exemplo, elas geralmente incluem ferramentas comerciais como XPLG ou SolarWinds Loggly. Ferramentas de análise automatizadas permitem o processamento e a análise de dados de logs. Essas ferramentas geralmente utilizam Inteligência Artificial/Aprendizado de Máquina para analisar padrões e tendências. À medida que o cenário de IA evolui, esperamos ver soluções de análise automatizadas mais eficazes.
![image](https://github.com/user-attachments/assets/db1971ed-32d6-4b93-924b-cdfa0f55987d)


Análise Manual:
Análise manual é o processo de examinar dados e artefatos sem usar ferramentas de automação. Por exemplo, um analista rolando por um log de servidor web seria considerado análise manual. A análise manual é essencial para um analista porque não se pode confiar em ferramentas de automação.
![image](https://github.com/user-attachments/assets/8e5d820b-f564-4257-ab71-52979d523652)


RESPOSTAS DA TAREFA 5
![image](https://github.com/user-attachments/assets/a3044a17-223f-40e2-a819-08b6fcec5d51)
EXPLICAÇÃO: A análise automatizada (automated) envolve o uso de ferramentas que processam os logs e retornam resultados automaticamente. Essas ferramentas geralmente utilizam inteligência artificial ou aprendizado de máquina para identificar padrões e tendências, economizando tempo e esforço manual.

![image](https://github.com/user-attachments/assets/0cf083e0-a462-4f5f-a700-8e7f34cb3d46)
EXPLICAÇÃO: A análise manual(MANUAL) é realizada diretamente por um analista que examina os logs sem o uso de ferramentas automatizadas. Nesse tipo de análise, o analista procura por eventos específicos, padrões de comportamento ou outras evidências de maneira manual, sendo mais demorado, porém permitindo um exame contextual e detalhado dos registros.


------------------------------------------------------------------------------------------------------------------------------------------------------------------------------


TAREFA 6


RESPOSTAS DA TAREFA 6
![image](https://github.com/user-attachments/assets/8c68ac73-caa4-4098-9bf0-1428cb89380a)
![image](https://github.com/user-attachments/assets/53f9f430-8c77-42f6-9d62-f37b0c5a1a37)
![image](https://github.com/user-attachments/assets/e12065d8-c567-42a4-b19d-9eaa32255d75)




