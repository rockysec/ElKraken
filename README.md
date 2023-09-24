![kraken](https://github.com/rockysec/Deploy_ElKraken/assets/48323046/720a236e-6681-4caa-a33c-0d0782ee7c0b)

# El Kraken
Herramienta automatizada para el proceso de recon activo/pasivo y explotacion de vulnerabilidades mediante el uso de herramientas opensource de la comunidad de bug bounty.

El Kraken es una herramienta desarrollada en bash scripting, la cual trabaja simil a un pulpo, tomando como input el output de otros procesos previos y con ello armar un pipeline de escaneos al target suministrado.

# Configuracion Inicial
1 - Descargar la herramienta en donde desees instalarla y ejecutarla:  
git clone https://github.com/rockysec/ElKraken

2 - Instalar las tools dependencias con el script ubicado en la carpeta ElKraken/Tools:  
cd ElKraken/Tools  
sudo bash install.sh  

3 - A modo opcional, configurar las APIKEYS en cada uno de los servicios de escaneo publicos, ejemplo censys, securitytrails, virustotal, etc. Esto ofrece mejores resultados obtenidos en el proceso de recon automatizado.  
Editar el archivo ElKraken/Tools/config.yaml tal como se muestra a continuacion:  

[...]  
censys:  
    - xxxxxxxyourapikeyxxxxxxxx  
certspotter:  
    - xxxxxxxyourapikeyxxxxxxxx  
chaos: [xxxxxxxyourapikeyxxxxxxxx]  
github:  
    - xxxxxxxyourapikeyxxxxxxxx  
intelx:  
    - xxxxxxxyourapikeyxxxxxxxx  
passivetotal:  
    - xxxxxxxyourapikeyxxxxxxxx  
recon: []  
robtex: []  
securitytrails:  
    - xxxxxxxyourapikeyxxxxxxxx  
shodan:  
    - xxxxxxxyourapikeyxxxxxxxx  
[...]  

Posterior a ello guardar el archivo en la ruta ./config/config.yaml  

Como ultima recomendacion de configuracion, estan las variables de configuracion dentro del archivo ElKrakenTool.sh alli podras configurar las siguientes variables para una mejor experiencia de uso:  
tokenSlack: Variable en donde debes usar el token para enviar las notificaciones del inicio y fin del escaneo via slack las cuales van a servir para un mayor control de las tareas  
channelSlack: Variable en donde debes usar el canal de slack al cual enviaras las notificaciones del inicio y fin del escaneo  
ssh_conection: Variable en donde indicaras algun servidor remoto al cual la herramienta se conectara via sftp para enviar los resultados de los escaneos, ejemplo, "user@ipaddress:/DestinationFolder". Esta funcionalidad se activa con el flag -output  

# Argumentos y Modo de uso:
sudo bash ElKrakenTool.sh -domain domain.com -recon -argumento [-domain ]  

-domain <dominio.com>: Argumento mandatorio para especificar el target a revisar  
-recon: Argumento mandatorio para proceso de recon via validacion dns, urls, etc  
-wayback: Realiza recopilacion de info con wayback url  
-dirsearch: Realiza fuzzing de directorios  
-nuclei_cves: Realiza scaneos con nuclei en busca de vulnerabilidades  
-nuclei_dlogins: Realiza scaneos con nuclei en busca de Default Logins  
-nuclei_panels: Realiza scaneos con nuclei en busca de panels de login  
-nuclei_exposures: Realiza scaneos con nuclei en busca de informacion expuesta  
-nuclei_misc: Realiza scaneos con nuclei en busca de misc  
-nuclei_misconfig: Realiza scaneos con nuclei en busca de misconfiguration  
-nuclei_takeovers: Realiza scaneos con nuclei en busca de posibles dns takeover  
-nuclei_tech: Realiza scaneos con nuclei en busca de deteccion de tecnologias usadas  
-nuclei_vuln: Realiza scaneos con nuclei en busca de vulnerabilidades varias  
-cors: Analiza si las url son vulnerables a Cors  
-nmap: Realiza scan a todos los puertos de manera agresiva en todos los subdominios  
-xss: Realiza busquedas de XSS  
-crlf: Realiza busqueda de vulnerabilidad CRLF  
-sqli: Realiza la busqueda de SQLi  
-or: Realiza la busqueda de Open Redirec   
-pp: Realiza la busqueda de Prototype Pollution  
-output: Envia la data recopilada al nodo de alamacenamiento de resultados  

Como recomendacion, recomiendo utilizar la herramienta tmux que sirve para generar sesiones virtuales, super util para evitar perder el avance de algun trabajo realizado en la consola ante una desconexion. Con ello te aseguras que ante una desconexion inminente no pierdas el proceso de escaneo que tengas en curso.  

Espero sea de utilidad la herramienta y pueda facilitar tu proceso de bug bounty.

Happy Hacking!!!
