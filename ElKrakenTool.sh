#!/bin/bash
############################################
#                                          #
#     Your APITokens and Variables here    #
#                                          #
############################################
dirsearchExtensions="sql,txt,zip,jsp,log,logs,old,tar.gz,gz,tar,tgz,bkp,dump,db,php,php3,php4,php5,,xml,py,asp,aspx,rar,do,1,asmx,rar,key,gpg,asc,pl,js,shtm,shtml,phtm,phtml,jhtml,cfm,cfml,rb,cfg,pdf,doc,docx,xls,xlsx,conf"
tokenSlack="YOUR_TOKEN"
channelSlack="YOUR_CHANNEL"
directory_tools=~/tools
directory_data=/root
ssh_conection="user@ipadd:/folder" ##Para conexion sftp entre servidor de scan y servidor repositorio de data
########################################


function logo {
echo " _____ _       _  ______      _    _  _______ _   _ "
echo "| ____| |     | |/ /  _ \    / \  | |/ / ____| \ | |"
echo "|  _| | |     | ' /| |_) |  / _ \ | ' /|  _| |  \| |"
echo "| |___| |___  | . \|  _ <  / ___ \| . \| |___| |\  |"
echo "|_____|_____| |_|\_\_| \_\/_/   \_\_|\_\_____|_| \_|"
echo ""
}

red=`tput setaf 1`
green=`tput setaf 2`
yellow=`tput setaf 3`
reset=`tput sgr0`
SECONDS=0
domain=$2
#subreport=
#usage() { echo -e "Usage: $0 -d domain [-e]\n  Select -e to specify excluded domains\n " 1>&2; exit 1; }
#while getopts ":d:e:r:" o; do
#    case "${o}" in
#        d)
#            domain=${OPTARG}
#            ;;

            #### working on subdomain exclusion
#        e)
#            excluded=${OPTARG}
#            ;;
#                r)
#            subreport+=("$OPTARG")
#            ;;
#        *)
#            usage
#            ;;
#    esac
#done

#shift $((OPTIND - 1))
#if [ -z "${domain}" ] && [[ -z ${subreport[@]} ]]; then
#   usage; exit 1;
#fi

function flags {
  echo "${yellow}Argumentos permitidos:"
  echo "-domain <argumento>: Realiza la tarea 1 con el argumento especificado"
  echo "-recon: Realiza validacion dns, urls, etc"
  echo "-wayback: Realiza recopilacion de info en wayback url"
  echo "-dirsearch: Realiza fuzzing de directorios"
  echo "-linkfinder: Realiza la busqueda de nuevos endpoints en archivos js"
  echo "-nuclei_cves: Realiza scaneos con nuclei en busca de vulnerabilidades"
  echo "-nuclei_dlogins: Realiza scaneos con nuclei en busca de Default Logins"
  echo "-nuclei_panels: Realiza scaneos con nuclei en busca de panels de login"
  echo "-nuclei_exposures: Realiza scaneos con nuclei en busca de informacion expuesta"
  echo "-nuclei_misc: Realiza scaneos con nuclei en busca de misc"
  echo "-nuclei_misconfig: Realiza scaneos con nuclei en busca de misconfiguration"
  echo "-nuclei_takeovers: Realiza scaneos con nuclei en busca de posibles dns takeover"
  echo "-nuclei_tech: Realiza scaneos con nuclei en busca de deteccion de tecnologias usadas"
  echo "-nuclei_vuln: Realiza scaneos con nuclei en busca de vulnerabilidades varias"
  echo "-cors: Analiza si las url son vulnerables a Cors"
  echo "-nmap: Realiza scan a todos los puertos de manera agresiva en todos los subdominios"
  echo "-xss: Realiza busquedas de XSS"
  echo "-crlf: Realiza busqueda de vulnerabilidad CRLF"
  echo "-sqli: Realiza la busqueda de SQLi"
  echo "-or: Realiza la busqueda de Open Redirecg"
  echo "-pp: Realiza la busqueda de Prototype Pollution"
  echo "-output: Envia la data recopilada al nodo de ELK"

}

logo
# Verificar si se pasaron argumentos
if [ $# -eq 0 ]; then
  echo "${red}Debe pasar al menos un argumento."
  flags
  exit 1
fi

# Variables de control
domain=""
recon=false
wayback=false
dirsearch=false
linkfinder=false
nuclei_cves=false
nuclei_dlogins=false
nuclei_panels=false
nuclei_exposures=false
nuclei_misc=false
nuclei_misconfig=false
nuclei_takeovers=false
nuclei_tech=false
nuclei_vuln=false
cors=false
nmap=false
xss=false
crlf=false
sqli=false
or=false
pp=false
output=false

while [[ $# -gt 0 ]]; do
    key="$1"

    case $key in

   -domain)
         if [ -z "$2" ]; then
        echo "${red}Falta el argumento para -domain."
        flags
        exit 1
      fi

      domain="$2"
      shift 2
      ;;

    -recon)
      recon=true
      shift
      ;;
    -wayback)
      wayback=true
      shift
      ;;
    -dirsearch)
      dirsearch=true
      shift
      ;;
    -nuclei_cves)
      nuclei_cves=true
      shift
      ;;
    -nuclei_dlogins)
      nuclei_dlogins=true
      shift
      ;;
    -nuclei_panels)
      nuclei_panels=true
      shift
      ;;
    -nuclei_exposures)
      nuclei_exposures=true
      shift
      ;;
    -nuclei_misc)
      nuclei_misc=true
      shift
      ;;
    -nuclei_misconfig)
      nuclei_misconfig=true
      shift
      ;;
    -nuclei_takeovers)
      nuclei_takeovers=true
      shift
      ;;
    -nuclei_tech)
      nuclei_tech=true
      shift
      ;;
    -nuclei_vuln)
      nuclei_vuln=true
      shift
      ;;
    -cors)
      cors=true
      shift
      ;;
    -nmap)
      nmap=true
      shift
      ;;
    -xss)
      xss=true
      shift
      ;;
    -crlf)
      crlf=true
      shift
      ;;
    -sqli)
      sqli=true
      shift
      ;;
    -or)
      or=true
      shift
      ;;
    -pp)
      pp=true
      shift
      ;;
    -output)
      output=true
      shift
      ;;
    *)
      echo "${red}Argumento invalido: $key"
      flags
      exit 1
      ;;
  esac
done

# Ejecutar tareas segun los flags
if [ "$recon" = true ]; then

  if [ -z "${domain}" ]; then
   domain=${subreport[1]}
   foldername=${subreport[2]}
   subd=${subreport[3]}
   report $domain $subdomain $foldername $subd; exit 1;
   fi
   clear
   logo
   if [ -d "$directory_data/$domain" ]
   then
     echo "${yellow}Este target fue escaneado previamente!."
     exit
   else
     mkdir $directory_data/$domain
fi

todate=$(date +"%Y-%m-%d")
path=$(pwd)
foldername=scan-$todate
  mkdir $directory_data/$domain/$foldername
  mkdir $directory_data/$domain/$foldername/nuclei
  mkdir $directory_data/$domain/$foldername/nmap

##############################################################################Discovery START############################################################################
  curl -F token=$tokenSlack -F channel=$channelSlack -F text="El runner a iniciado el scan en $domain!" https://slack.com/api/chat.postMessage
  echo "${green}Recon started in Subdomain $domain ${reset}"
  echo "${green}Listing subdomains using Sublist3r..."
  python3 $directory_tools/Sublist3r/sublist3r.py -d $domain -t 10 -v -o $directory_data/$domain/$foldername/$domain.txt > /dev/null
  echo "Listing subdomains using subfinder..."
  subfinder -all -silent -d $domain -oI -nW > $directory_data/$domain/$foldername/subdomain_ip.csv
  cat $directory_data/$domain/$foldername/subdomain_ip.csv | sed "s/[,].*//" | sort -u >> $directory_data/$domain/$foldername/$domain.txt
  echo "${green}Probing for live hosts..."
  echo $domain >> $directory_data/$domain/$foldername/$domain.txt
  cat $directory_data/$domain/$foldername/$domain.txt | httpx >> $directory_data/$domain/$foldername/responsive.txt
  cat $directory_data/$domain/$foldername/responsive.txt >> $directory_data/$domain/$foldername/urllist.csv
  cp $directory_data/$domain/$foldername/$domain.txt $directory_data/$domain/$foldername/subdomain.csv
  echo  "${yellow}Total of $(wc -l $directory_data/$domain/$foldername/urllist.csv | awk '{print $1}') live subdomains were found${reset}"
fi



##############################################################################wayback START############################################################################
if [ "$wayback" = true ]; then
#echo "${green}Starting to check available data in wayback machine"
waybackurls $domain > $directory_data/$domain/$foldername/wayback_tmp.txt
cat $directory_data/$domain/$foldername/wayback_tmp.txt | sort -u | uro > $directory_data/$domain/$foldername/wayback.txt
rm $directory_data/$domain/$foldername/wayback_tmp.txt
fi

##############################################################################Dirsearch START############################################################################
if [ "$dirsearch" = true ]; then
echo "${green}Starting to check discovery with dirsearch"
dirsearch -w ~/tools/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -e $dirsearchExtensions -t 50 -exclude 403,401,404,400 -l $directory_data/$domain/$foldername/urllist.csv --deep-recursive -R 4 --crawl --full-url  --no-color --format=csv -o $directory_data/$domain/$foldername/dirsearch.csv
fi

##############################################################################Dirsearch START############################################################################
if [ "$pp" = true ]; then
echo "${green}Starting to check Prototype Pollution"
subfinder -d $domain -all -silent | httpx -silent -threads 300 | anew -q alive.txt && sed 's/$/\/?__proto__[testparam]=exploit\//' alive.txt | page-fetch -j 'window.testparam == "exploit"? ", VULNERABLE" : ", NOT VULNERABLE"' | sed "s/(//g" | sed "s/)//g" | sed "s/JS //g" | grep "VULNERABLE" > $directory_data/$domain/$foldername/prototype_pollution.csv
rm alive.txt
fi

##############################################################################OpenRedirect START############################################################################
if [ "$or" = true ]; then
echo "${green}Starting to check Open Redirect"
waybackurls $domain | grep -a -i \=http | qsreplace 'http://evil.com' | while read host do;do curl -s -L $host -I| echo -e "$host" ;done >> openredirect.csv 2>/dev/null
fi

##############################################################################nuclei START############################################################################
if [ "$nuclei_cves" = true ]; then
echo "{green}Starting to check cves"
nuclei -l $directory_data/$domain/$foldername/urllist.csv -no-color -t cves | sed 's/ /,/g; s/\[//g; s/\]//g; s/(//g; s/)//g' > $directory_data/$domain/$foldername/nuclei.csv
fi

if [ "$nuclei_dlogins" = true ]; then
echo "{green}Starting to check default logins"
nuclei -l $directory_data/$domain/$foldername/urllist.csv -no-color -t default-logins | sed 's/ /,/g; s/\[//g; s/\]//g; s/(//g; s/)//g' >> $directory_data/$domain/$foldername/nuclei.csv
fi

if [ "$nuclei_panels" = true ]; then
echo "{green}Starting to check exposed panels"
nuclei -l $directory_data/$domain/$foldername/urllist.csv -no-color -t exposed-panels | sed 's/ /,/g; s/\[//g; s/\]//g; s/(//g; s/)//g' >> $directory_data/$domain/$foldername/nuclei.csv
fi

if [ "$nuclei_exposures" = true ]; then
echo "{green}Starting to check exposed information"
nuclei -l $directory_data/$domain/$foldername/urllist.csv -no-color -t exposures | sed 's/ /,/g; s/\[//g; s/\]//g; s/(//g; s/)//g' >> $directory_data/$domain/$foldername/nuclei.csv
fi

if [ "$nuclei_misc" = true ]; then
echo "{green}Starting to check miscellaneous"
nuclei -l $directory_data/$domain/$foldername/urllist.csv -no-color -t miscellaneous | sed 's/ /,/g; s/\[//g; s/\]//g; s/(//g; s/)//g' >> $directory_data/$domain/$foldername/nuclei.csv
fi

if [ "$nuclei_misconfig" = true ]; then
echo "{green}Starting to check misconfiguration"
nuclei -l $directory_data/$domain/$foldername/urllist.csv -no-color -t misconfiguration | sed 's/ /,/g; s/\[//g; s/\]//g; s/(//g; s/)//g' >> $directory_data/$domain/$foldername/nuclei.csv
fi

if [ "$nuclei_takeovers" = true ]; then
echo "{green}Starting to check DNS Takeovers"
nuclei -l $directory_data/$domain/$foldername/urllist.csv -no-color -t takeovers | sed 's/ /,/g; s/\[//g; s/\]//g; s/(//g; s/)//g' >> $directory_data/$domain/$foldername/nuclei.csv
fi

if [ "$nuclei_tech" = true ]; then
echo "{green}Starting to check technologies"
nuclei -l $directory_data/$domain/$foldername/urllist.csv -no-color -t technologies | sed 's/ /,/g; s/\[//g; s/\]//g; s/(//g; s/)//g' >> $directory_data/$domain/$foldername/nuclei.csv
fi

if [ "$nuclei_vuln" = true ]; then
echo "{green}Starting to check vulnerabilities"
nuclei -l $directory_data/$domain/$foldername/urllist.csv -no-color -t vulnerabilities | sed 's/ /,/g; s/\[//g; s/\]//g; s/(//g; s/)//g' >> $directory_data/$domain/$foldername/nuclei.csv
fi


##############################################################################CORS START############################################################################
if [ "$cors" = true ]; then
echo "{green}Starting to check CORS vulnerabilities"
python3 $directory_tools/Corsy/corsy.py -i $directory_data/$domain/$foldername/urllist.csv -o $directory_data/$domain/$foldername/cors.json
fi


##############################################################################Port Scan START############################################################################
if [ "$nmap" = true ]; then
echo "{green}Starting to check Open Ports"
bash $directory_tools/customscripts/loop_nmap.sh $directory_data/$domain/$foldername/subdomain.csv
mv $directory_data/nmap_full_* $directory_data/$domain/$foldername/nmap/
fi


##############################################################################XSS START############################################################################
if [ "$xss" = true ]; then
echo "{green}Starting to check XSS"

 cat $directory_data/$domain/$foldername/urllist.csv | dalfox pipe --remote-wordlists=burp,assetnote  --report-format json --poc-type='curl' --output $directory_data/$domain/$foldername/dalfox_subdomains_tmp.txt
 cat $directory_data/$domain/$foldername/dalfox_subdomains_tmp.txt | awk '{print $5}' > $directory_data/$domain/$foldername/dalfox.txt
 rm $directory_data/$domain/$foldername/dalfox_subdomains_tmp.txt

 cat $directory_data/$domain/$foldername/new_endpoint.txt | dalfox pipe --remote-wordlists=burp,assetnote  --report-format json --poc-type='curl' --output $directory_data/$domain/$foldername/dalfox_new_endpoint_tmp.txt

 cat $directory_data/$domain/$foldername/dalfox_new_endpoint_tmp.txt | awk '{print $5}' >> $directory_data/$domain/$foldername/dalfox.txt
 rm $directory_data/$domain/$foldername/dalfox_new_endpoint_tmp.txt

 cat $directory_data/$domain/$foldername/wayback.txt | dalfox pipe --remote-wordlists=burp,assetnote  --report-format json --poc-type='curl' --output $directory_data/$domain/$foldername/dalfox_wayback_tmp.txt
 cat $directory_data/$domain/$foldername/dalfox_wayback_tmp.txt | awk '{print $5}' >> $directory_data/$domain/$foldername/dalfox.txt
 rm $directory_data/$domain/$foldername/dalfox_wayback_tmp.txt
fi


##############################################################################CRLF START############################################################################
if [ "$crlf" = true ]; then
echo "{green}Starting to check CRLF"
 crlfuzz -l $directory_data/$domain/$foldername/urllist.csv -o $directory_data/$domain/$foldername/crlfuzz_urllist.csv
 crlfuzz -l $directory_data/$domain/$foldername/wayback.txt -o $directory_data/$domain/$foldername/crlfuzz_wayback.txt
 cat $directory_data/$domain/$foldername/crlfuzz_urllist.csv > $directory_data/$domain/$foldername/crlfuzz.txt
 cat $directory_data/$domain/$foldername/crlfuzz_wayback.txt >> $directory_data/$domain/$foldername/crlfuzz.txt
 rm $directory_data/$domain/$foldername/crlfuzz_urllist.csv  $directory_data/$domain/$foldername/crlfuzz_wayback.txt
fi


##############################################################################SQLi START############################################################################
if [ "$sqli" = true ]; then
 echo "{green}Starting to check SQLi Vulnerabilities"
 gf sqli $directory_data/$domain/$foldername/wayback.txt $directory_data/$domain/$foldername/urllist.csv >> $directory_data/$domain/$foldername/sqli_candidates.txt 
 python $directory_tools/sqlmap/sqlmap.py -m $directory_data/$domain/$foldername/sqli_candidates.txt --dbs --batch > $directory_data/$domain/$foldername/sqli_tmp.txt
 bash $directory_data/$domain/$foldername/parse_sqli.sh 
 mv $directory_data/sqli.csv $directory_data/$domain/$foldername/
 rm $directory_data/$domain/$foldername/sqli_candidates.txt
fi


##############################################################################Output START############################################################################
if [ "$output" = true ]; then
 scp -o  StrictHostKeyChecking=no -r ~/$domain $ssh_conection
 echo "{yellow}The recopiled data was moved to the Master node"
 curl -F token=$tokenSlack -F channel=$channelSlack -F text="Los resultados se movieron al Backoffice para ser indexados. Fue un total de $(wc -l $directory_data/$domain/$foldername/urllist.csv | awk '{print $1}') URLs activas encontradas." https://slack.com/api/chat.postMessage
fi
