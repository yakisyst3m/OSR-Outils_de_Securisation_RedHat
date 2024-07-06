#/bin/bash

# github.com/yakisyst3m/OSR-Outils_de_Securisation_RedHat

# 2022 03 11    v1.0-beta    Création du programme
# 2022 03 12    v1.0-beta    début menu + fonctions + SSH en cours
# 2022 03 14    v1.0-beta    Modif varivales du début + config IPv4 + SSH + couleurs + checks à chaque étape
# 2022 03 15    v1.0-beta    menu 1 2 3 4 5 6 ont été modifiés puis testés
# 2024 07 06    v1.1         Modif des controles

#SOMMAIRE
#---------

    #- Carte Réseau
    #- Reboot service NetworkManager
    #- test RZO
    #- MAJ paquets + OS
    #- Désactivation IPv6
    #- Modif hostname
    #- Sécurisation Grub
    #- Sécurisation SSH
    #- selinux ssh
    #- firewalld ssh


#VARIABLES
#---------

    IPV4INTERNETDNS="1.1.1.1"
    
    ETHNAME=$(ip a | grep "2: en" | tr " " ":" | awk -F ":" '{print $3}')
    ETHCHEMIN="/etc/sysconfig/network-scripts/ifcfg-$ETHNAME"
    ETHUUID=$(nmcli con show | grep eth | awk -F " " '{print $2}')
    
    SYSCTL="/etc/sysctl.conf"
    SSHCHEMIN="/etc/ssh/sshd_config"

    rouge='\e[1;31m'
    vert='\e[1;32m'
    jaune='\e[1;33m'
    bleu='\e[1;34m'
    violet='\e[1;35m'
    neutre='\e[0;m'
    bleufondjaune='\e[7;44m\e[1;33m'


#FONCTIONS
#----------
	function modifIpMaskGw() {
		# Configuration IPv4
        # --------------------
		echo -e "\n${bleu}[ ---- Configuration réseau en IPv4 ---- ]${neutre}\n"
		echo -e "Les paramètres IP actuels : "
		ip a
		echo -e "\n${violet}Ces paramètres vous conviennent-ils ? ( y pour quitter la config IP / n pour changer les IP )${neutre}\n"
		
		read -r choixip
		if [[ "$choixip" == "n" ]]; then
			read -p "Entrer une adresse IP STATIQUE : " IPV4SRV
			read -p "Entrer le masque réseau : " NETMASK
			read -p "Voulez-vous configurer une adresse de passerelle ? ( y / n ) : " validegw

			GW=""
			if [[ "$validegw" == "y" ]]; then
				read -p "Entrer l'adresse IP de la passerelle : " GW
			fi

			if [[ -f "$ETHCHEMIN" ]]; then
				sed -ri "s/^(|#)ONBOOT=.{1,}/ONBOOT=yes/" "$ETHCHEMIN"
				IPDHCP=$(grep -E "^(|#)BOOTPROTO=(dhcp|static|)" "$ETHCHEMIN")
				
				if [[ "$IPDHCP" = "BOOTPROTO=dhcp" ]]; then 
					read -p "Vous êtes en DHCP, voulez-vous rester en DHCP ? ( y pour DHCP / n pour STATIC) : " DHCPREPONSE
					if [[ "$DHCPREPONSE" == "n" ]]; then
						sed -ri "s/^(|#)BOOTPROTO=(dhcp|static|)/BOOTPROTO=static/" "$ETHCHEMIN"
						if ! sed -i "/BOOTPROTO=static/a ADDRESS=$IPV4SRV\nNETMASK=$NETMASK\n#GATEWAY=$GW" "$ETHCHEMIN"; then
							echo -e "\n${rouge}[ NOK ] - Erreur dans le fichier $ETHCHEMIN ${neutre}\n"
							return 1
						fi
						echo -e "\n${vert}[ OK ]\nIP=$IPV4SRV\nNETMASK=$NETMASK\n#GATEWAY=$GW ${neutre}\n"
					fi
				elif [[ "$IPDHCP" = "BOOTPROTO=static" ]]; then 
					sed -ri "s/^(|#)BOOTPROTO=(dhcp|static|)/BOOTPROTO=static/" "$ETHCHEMIN"
					if ! sed -i "/BOOTPROTO=static/a ADDRESS=$IPV4SRV\nNETMASK=$NETMASK\n#GATEWAY=$GW" "$ETHCHEMIN"; then
						echo -e "\n${rouge}[ NOK ] - Erreur dans le fichier $ETHCHEMIN ${neutre}\n"
						return 1
					fi
					echo -e "\n${vert}[ OK ]\nIP=$IPV4SRV\nNETMASK=$NETMASK\n#GATEWAY=$GW ${neutre}\n"
				fi
			else
				echo -e "\n${rouge}[ NOK - ]Le chemin de la carte réseau n'existe pas vérifier les paramètres réseaux : ${neutre}\n"
				ip a | grep "$IPV4SRV" -A3
				echo -e "- La carte réseau Ethernet est-elle présente ?\n- Est-elle bien connectée physiquement ?\n- Vérifier sur Internet l'existence d'un pilote."
				echo -e "\n${rouge} Fin de la configuration IP : les paramètres IP n'ont pas été changés car une erreur existe sur la connectivité physique.${neutre}\n"
			fi
		else
			echo -e "${violet}--- Fin des paramètres IP ---${neutre}\n"
		fi
	}

		#--------------------------------------------------

	function restartRZO() {
		# Redémarrage service réseau
		# ----------------------------
		echo -e "\n${bleu}[ ---- Redémarrage des services réseaux ---- ]${neutre}\n"
		systemctl restart NetworkManager && echo -e "\n${vert}[ OK ] - Service réseau redémarré ${neutre}\n" || echo -e "\n${rouge}[ NOK ] - Erreur de service réseau ${neutre}\n"
	}

		#--------------------------------------------------

	function testINTERNET() {
		# Test de connectivité Internet
		# -------------------------------
		echo -e "\n${bleu}[ ---- Test réseau ---- ]${neutre}\n"
		ping -c1 $IPV4INTERNETDNS
		TEST1=$?
		if [ $TEST1 -eq 0 ] ; then
			echo -e "${vert} [ OK ] Réseau Internet opérationnel : poursuite de la configuration ${neutre}"
			sleep 2
		else
			echo -e "${rouge} [ NOK ] Vérifier le réseau ${neutre}"
			echo "Arrêt du script dans 5 secondes"
			exit
		fi
    }

    #--------------------------------------------------

    function MAJOS() {
        # Mise à jour paquets et distribution
        # -----------------------------------
        echo -e "\n${bleu}[ ---- Mise à jour paquets et distribution ---- ]${neutre}\n"
        yum update -y && echo -e "\n${vert}[ OK ] - Les paquets sont à jour ${neutre}\n" || echo -e "\n${rouge}[ NOK ] - Erreur sur la mise à jour des paquets ${neutre}\n"
    }


    #--------------------------------------------------

    function desactivIPV6() {
        #DESACTIVATION IPV6
        # -------------------
        echo -e "\n${bleu}[ ---- Désactivation de l'IPv6 ---- ]${neutre}\n"
        
        sed -ri  "s/^IPV6/#IPV6/g" $ETHCHEMIN && echo -e "${vert} [ OK ] Ligne IPV6 désactivées dans le fichier $ETHCHEMIN ${neutre}"

        grep -q 'net.ipv6.conf.all.disable_ipv6' $SYSCTL
        if [ "$?" = "0" ] ; then # si la ligne existe / -q pour mode silencieux, ne note rien à l'écran
            sed -ri 's/^(|#)net\.ipv6\.conf\.all\.disable_ipv6=(0|1|)/net\.ipv6\.conf\.all\.disable_ipv6=1/g' $SYSCTL  && echo -e "${vert} [ OK ] net.ipv6.conf.all.disable_ipv6=1 : paramétré ${neutre}"
        else 
            echo "net.ipv6.conf.all.disable_ipv6=1" >> $SYSCTL && echo -e "${vert} [ OK ] net.ipv6.conf.all.disable_ipv6=1 : paramétré ${neutre}"
        fi

        grep -q 'net.ipv6.conf.all.autoconf' $SYSCTL
        if [ "$?" = "0" ] ; then 
            sed -ri 's/^(|#)net\.ipv6\.conf\.all\.autoconf=(0|1|)/net\.ipv6\.conf\.all\.autoconf=0/g' $SYSCTL  && echo -e "${vert} [ OK ] net.ipv6.conf.all.autoconf=0 : paramétré ${neutre}"
        else
            echo "net.ipv6.conf.all.autoconf=0" >> $SYSCTL  && echo -e "${vert} [ OK ] net.ipv6.conf.all.autoconf=0 : paramétré ${neutre}"
        fi

        grep -q 'net.ipv6.conf.default.disable_ipv6' $SYSCTL
        if [ "$?" = "0" ] ; then
            sed -ri 's/^(|#)net\.ipv6\.conf\.default\.disable_ipv6=(0|1|)/net\.ipv6\.conf\.default\.disable_ipv6=1/g' $SYSCTL  && echo -e "${vert} [ OK ] net.ipv6.conf.default.disable_ipv6=1 : paramétré ${neutre}"
        else
            echo "net.ipv6.conf.default.disable_ipv6=1" >> $SYSCTL  && echo -e "${vert} [ OK ] net.ipv6.conf.default.disable_ipv6=1 : paramétré ${neutre}"
        fi

        grep -q 'net.ipv6.conf.default.autoconf' $SYSCTL
        if [ "$?" = "0" ] ; then
            sed -ri 's/^(|#)net\.ipv6\.conf\.default\.autoconf=(0|1|)/net\.ipv6\.conf\.default\.autoconf=0/g' $SYSCTL  && echo -e "${vert} [ OK ] net.ipv6.conf.default.autoconf=0 : paramétré ${neutre}"
        else
            echo "net.ipv6.conf.default.autoconf=0" >> $SYSCTL  && echo -e "${vert} [ OK ] net.ipv6.conf.default.autoconf=0 : paramétré ${neutre}"
        fi
        echo -e "\n${bleufondjaune}Validation de la configuration${neutre}\n"
        sysctl -p
    }

    #--------------------------------------------------

    function modifHOSTNAME() {
        # MODIF HOSTNAME
        # ----------------
        echo -e "\n${bleu}[ ---- Modification du nom de machine ---- ]${neutre}\n"
        read -p "Entrer le nom de machine : " MYHOSTNAME ;
        hostnamectl set-hostname $MYHOSTNAME && echo -e "${vert}[ OK ] - Renommage du serveur effectué : $MYHOSTNAME ${neutre}" 
    }
    
    #--------------------------------------------------
           
   function secuGRUB2() {
        #SECURISATION DE GRUB 2
        # -----------------------
        echo -e "\n${bleu}[ ---- Sécurisation de Grub 2 ---- ]${neutre}\n"
        echo -e "Pour sécuriser le GRUB vous aurez besoin d'un \"login\" et d'un \"mot de passe\".\n"
        read -p "Entrer le login ${rouge}(Attention au boot le clavier sera en QWERTY pour le login et le mot de passe) : ${neutre}\n" logingrub
        grub2-mkpasswd-pbkdf2 | tee -a /etc/grub.d/40_custom
        sed -i '/Entrez/d' /etc/grub.d/40_custom
        sed -ri "s/(^L[a-zA-Z0-9]).{1,}est\ /password_pbkdf2\ $logingrub\ /g" /etc/grub.d/40_custom
        sed -i "/password/i #Password\nset superusers=\"$logingrub\"" /etc/grub.d/40_custom && echo -e "${vert}[ OK ] - Votre login dans la config linux est : $(grep  -Ei '^set superusers' /etc/grub.d/40_custom | awk -F " " '{print $2}' | awk -F "\"" '{print $2}')${neutre}\n" || echo -e "\n${rouge}[ NOK ] - Erreur de Login${neutre}\n"
        sleep 4
        grub2-mkconfig -o /boot/grub2/grub.cfg
  }
    #--------------------------------------------------
    
    function seLINUX() {
        #VERIFICATION SELINUX EN PLACE SINON MISE EN PLACE
        # -------------------------------------------------
        echo -e "\n${bleu}[ ---- Vérification de la mise en place de SeLinux ---- ]${neutre}\n"
        if [ "$(getenforce)" = "Enforcing" ] ; then
            echo -e "\n${vert}[ OK ] - SeLinux est paramétré sur Enforcing${neutre}"
            sleep 2
        else
            sed '/SELINUX=/d' /etc/selinux/config | sed '/# SELINUXTYPE/i SELINUX=Enforcing'
            touch /.autorelabel
            echo -e -e "\n${violet}Dans 5 secondes :    Rédémarrage du serveur pour valider la prise en compte du type : Enforcing SELINUX${neutre}"
            sleep 5
            reboot
        fi
    }

    #--------------------------------------------------

    function restartSSH() {
        # Redémarrage service SSH
        # -------------------------
        echo -e "\n${bleu}[ ---- Redémarrage service SSH ---- ]${neutre}\n"
        systemctl restart sshd.service && echo -e "\n${vert}[ OK ] - Service SSH redémarré ${neutre}\n" || echo -e "\n${rouge}[ NOK ] - Erreur de service SSH ${neutre}\n"
    }
  
    #--------------------------------------------------
       
   function secuSSH() {
        # Test pour voir l'installation de openssh
        SSHINSTALL=$(yum list installed | grep -oE '^openssh-server' | awk -F " " '{print $1}')
        if [ "$SSHINSTALL" != "openssh-server" ] ; then
            # voir la connectivité internet
            testINTERNET
            #installation du serveur SSH
            yum install -y openssh-server openssh-clients
        fi
   
        #SECURISATION DE BASE POUR SSH      RECOMMANDATIONS ANSSI
        # -------------------------------
        echo -e "\n${bleu}[ ---- Sécurisation de Base pour SSH ---- ]${neutre}\n"
        
        # Changement du port SSH
        PORTSSH=$(grep -Ei '(^p|^#)ort' $SSHCHEMIN | cut -d " " -f2)
        echo -e "Le port actuel est le port : $PORTSSH"
        grep -qE '^(|#|# )Port 22' $SSHCHEMIN
        if [ "$?" = "0" ] ; then
            read -p "Entrer un nouveau numéro de port : " PORTSSHNOUVEAU
            sed -i "s/#Port 22/Port $PORTSSHNOUVEAU/" $SSHCHEMIN                                   # Modification du port de base 22 
            echo -e "\n${vert}[ OK ] - Port SSH : $(grep -Ei '^Port' $SSHCHEMIN | awk -F " " '{print $2}') ${neutre}\n" || echo -e "\n${rouge}[ NOK ] - Erreur de Port${neutre}\n"
        else
            echo -e "\n${bleufondjaune}[ OK - pas de changement ] - Port SSH : $(grep -Ei '^Port' $SSHCHEMIN | awk -F " " '{print $2}') ${neutre}\n"
        fi
        sleep 2
        
        # Changement de l'adresse IP en écoute
        SSHIPECOUTE=$(grep -Ei '(^l|^#)istenaddress' $SSHCHEMIN | cut -d " " -f2)
        echo -e "L'adresse IP en écoute est actuelle : $SSHIPECOUTE\n"
        sleep 2
        grep -qE '^(|#|# )ListenAddress 0.0.0.0' $SSHCHEMIN 
        if [ "$?" = "0" ] ; then
            sed -i "s/#ListenAddress 0.0.0.0/ListenAddress $IPV4SRV/" $SSHCHEMIN            # Adresse IP du serveur en écoute
            echo -e "La nouvelle adresse IP mise est celle du serveur : $IPV4SRV"
            IPSSHNETSTAT=$(netstat -taupn | grep ssh | awk -F " " '{print $4}' | cut -d ":" -f1)
            ping -c1 $IPSSHNETSTAT | grep -q '1 received, 0% packet loss' && echo -e "\n${vert}[ OK ] - IP en encoute : $(grep -Ei '^ListenAddress' $SSHCHEMIN | cut -d " " -f2)${neutre}\n" || echo -e "\n${rouge}[ NOK ] - Erreur de ListenAddress${neutre}\n"
        else
            echo -e "\n${bleufondjaune}[ OK - pas de changement ] - IP en encoute : $(grep -Ei '^ListenAddress' $SSHCHEMIN | cut -d " " -f2)${neutre}\n"
        fi
        sleep 2
        
        # On force SSH en version 2
        grep -qE '^Protocol 2' $SSHCHEMIN 
        if [ "$?" != "0" ] ; then
            sed -ri '/^ListenAddress/a Protocol 2' $SSHCHEMIN                               # Forcer le protocole V2 de SSH
            echo -e "Ajout du Protocol Version 2 :"
            echo -e "\n${vert}[ OK ] - Protocol : $(grep -Ei '^protocol' $SSHCHEMIN)${neutre}\n" || echo -e "\n${rouge}[ NOK ] - Erreur de version de Protocol${neutre}\n"
        else
            echo -e "\n${bleufondjaune}[ OK - pas de changement ] - Protocol : $(grep -Ei '^protocol' $SSHCHEMIN)${neutre}\n"
        fi
        sleep 2
        
        # Temps pour valider l'authentification SSH
        grep -qE '^(|#|# )LoginGraceTime 2m' $SSHCHEMIN 
        if [ "$?" = "0" ] ; then
            sed -i 's/#LoginGraceTime 2m/LoginGraceTime 30/' $SSHCHEMIN                     # Temps pour valider l'authentification SSH, si supérieur, connexion (CNX) refusée
            echo -e "\n${vert}[ OK ] - Temps pour valider l'authentification (après ce tps connexion refusée : $(grep -Ei '^LoginGraceTime' $SSHCHEMIN | awk -F " " '{print $2}') secondes${neutre}\n" || echo -e "\n${rouge}[ NOK ] - Erreur de LoginGraceTime${neutre}\n"
        else
            echo -e "\n${bleufondjaune}[ OK - pas de changement ] - Temps pour valider l'authentification (après ce tps connexion refusée : $(grep -Ei '^LoginGraceTime' $SSHCHEMIN | awk -F " " '{print $2}') secondes${neutre}\n"
        fi
        sleep 2
        
        # Nombre de CNX simultanées multiplexées par tunnel
        grep -qE '^MaxSessions 2' $SSHCHEMIN
        if [ "$?" != "0" ] ; then
            sed -i 's/#MaxSessions 10/MaxSessions 2/' $SSHCHEMIN                            # Nombre de CNX simultanées multiplexées par tunnel
            echo -e "\n${vert}[ OK ] - Nombre de CNX simultanées multiplexées par tunnel : $(grep -Ei '^MaxSessions' $SSHCHEMIN| awk -F " " '{print $2}')${neutre}\n" || echo -e "\n${rouge}[ NOK ] - Erreur de MaxSessions${neutre}\n"
        else
            echo -e "\n${bleufondjaune}[ OK - pas de changement ] - Nombre de CNX simultanées multiplexées par tunnel : $(grep -Ei '^MaxSessions' $SSHCHEMIN| awk -F " " '{print $2}')${neutre}\n"
        fi
        sleep 2
        
        # Nombre d'ahthentifications possibles avant de relancer la commande
        grep -qE '^MaxAuthTries 2' $SSHCHEMIN
        if [ "$?" != "0" ] ; then
            sed -i 's/#MaxAuthTries 6/MaxAuthTries 2/' $SSHCHEMIN                           # Nombre d'ahthentifications possibles avant de relancer la commande : 2
            echo -e "\n${vert}[ OK ] - Nombre d'ahthentifications possibles avant de relancer la commande : $(grep -Ei '^MaxAuthTries' $SSHCHEMIN | awk -F " " '{print $2}')${neutre}\n" || echo -e "\n${rouge}[ NOK ] - Erreur de MaxAuthTries${neutre}\n"
        else
            echo -e "\n${bleufondjaune}[ OK - pas de changement ] - Nombre d'ahthentifications possibles avant de relancer la commande : $(grep -Ei '^MaxAuthTries' $SSHCHEMIN | awk -F " " '{print $2}')${neutre}\n"
        fi
        sleep 2
        
        # Interdire le CNX SSH avec le compte root
        grep -qE '^(|#|# )PermitRootLogin yes' $SSHCHEMIN
        if [ "$?" = "0" ] ; then
            sed -i 's/PermitRootLogin yes/PermitRootLogin no/' $SSHCHEMIN                   # Interdire le CNX SSH avec le compte root
            echo -e "\n${vert}[ OK ] - Autoriser \"root\" à initier une connexion SSH : $(grep -Ei '^PermitRootLogin' $SSHCHEMIN | awk -F " " '{print $2}')${neutre}\n" || echo -e "\n${rouge}[ NOK ] - Erreur de PermitRootLogin${neutre}\n"
        else
            echo -e "\n${bleufondjaune}[ OK - pas de changement ] - Autoriser \"root\" à initier une connexion SSH : $(grep -Ei '^PermitRootLogin' $SSHCHEMIN | awk -F " " '{print $2}')${neutre}\n" 
        fi
        sleep 2
        
        # Interdire les mots de passe vides
        grep -qE '^PermitEmptyPasswords no' $SSHCHEMIN
        if [ "$?" != "0" ] ; then
            sed -i 's/#PermitEmptyPasswords no/PermitEmptyPasswords no/' $SSHCHEMIN         # Interdire les mots de passe vides
            echo -e "\n${vert}[ OK ] - Autoriser les mots de passe vides : $(grep -Ei '^PermitEmptyPasswords' $SSHCHEMIN | awk -F " " '{print $2}')${neutre}\n" || echo -e "\n${rouge}[ NOK ] - Erreur de PermitEmptyPasswords${neutre}\n"
        else
            echo -e "\n${bleufondjaune}[ OK - pas de changement ] - Autoriser les mots de passe vides : $(grep -Ei '^PermitEmptyPasswords' $SSHCHEMIN | awk -F " " '{print $2}')${neutre}\n"
        fi
        sleep 2
        
        # Interdire la redirection d'agent
        grep -qE '^AllowAgentForwarding no' $SSHCHEMIN
        if [ "$?" != "0" ] ; then
            sed -i 's/#AllowAgentForwarding yes/AllowAgentForwarding no/' $SSHCHEMIN        # Interdire la redirection d'agent
            echo -e "\n${vert}[ OK ] - Autoriser la redirection d'agent : $(grep -Ei '^AllowAgentForwarding' $SSHCHEMIN | awk -F " " '{print $2}')${neutre}\n" || echo -e "\n${rouge}[ NOK ] - Erreur de AllowAgentForwarding${neutre}\n"
        else
            echo -e "\n${bleufondjaune}[ OK - pas de changement ] - Autoriser la redirection d'agent : $(grep -Ei '^AllowAgentForwarding' $SSHCHEMIN | awk -F " " '{print $2}')${neutre}\n"
        fi
        sleep 2
        
        # Interdire la redirection des flux TCP
        grep -qE '^AllowTcpForwarding no' $SSHCHEMIN
        if [ "$?" != "0" ] ; then
            sed -i 's/#AllowTcpForwarding yes/AllowTcpForwarding no/' $SSHCHEMIN            # Interdire la redirection des flux TCP
            echo -e "\n${vert}[ OK ] - Autoriser la redirection des flux TCP : $(grep -Ei '^AllowTcpForwarding' $SSHCHEMIN | awk -F " " '{print $2}')${neutre}\n" || echo -e "\n${rouge}[ NOK ] - Erreur de AllowTcpForwarding${neutre}\n"
        else
            echo -e "\n${bleufondjaune}[ OK - pas de changement ] - Autoriser la redirection des flux TCP : $(grep -Ei '^AllowTcpForwarding' $SSHCHEMIN | awk -F " " '{print $2}')${neutre}\n"
        fi
        sleep 2
        
        # Interdire la redirection graphique X11
        grep -qE '^X11Forwarding no' $SSHCHEMIN
        if [ "$?" != "0" ] ; then
            sed -i 's/X11Forwarding yes/X11Forwarding no/' $SSHCHEMIN                       # Interdire la redirection graphique X11
            echo -e "\n${vert}[ OK ] - Autoriser la redirection graphique X11 : $(grep -Ei '^X11Forwarding' $SSHCHEMIN | awk -F " " '{print $2}')${neutre}\n" || echo -e "\n${rouge}[ NOK ] - Erreur de X11Forwarding${neutre}\n"
        else
            echo -e "\n${bleufondjaune}[ OK - pas de changement ] - Autoriser la redirection graphique X11 : $(grep -Ei '^X11Forwarding' $SSHCHEMIN | awk -F " " '{print $2}')${neutre}\n"
        fi
        sleep 2
        
        # A la CNX visualiser la date/heure de dernière CNX
        grep -qE '^PrintLastLog yes' $SSHCHEMIN
        if [ "$?" != "0" ] ; then
            sed -i 's/#PrintLastLog yes/PrintLastLog yes/' $SSHCHEMIN                       # A la CNX visualiser la date/heure de dernière CNX
            echo -e "\n${vert}[ OK ] - Afficher à la connexion la date et l'heure de dernière connexion : $(grep -Ei '^PrintLastLog' $SSHCHEMIN | awk -F " " '{print $2}')${neutre}\n" || echo -e "\n${rouge}[ NOK ] - Erreur de PrintLastLog${neutre}\n"
        else
            echo -e "\n${bleufondjaune}[ OK - pas de changement ] - Afficher à la connexion la date et l'heure de dernière connexion : $(grep -Ei '^PrintLastLog' $SSHCHEMIN | awk -F " " '{print $2}')${neutre}\n"
        fi
        sleep 2
        
        # Ne pas permettre le changement des variables d'environnement
        grep -qE '^PermitUserEnvironment no' $SSHCHEMIN
        if [ "$?" != "0" ] ; then
            sed -i 's/#PermitUserEnvironment no/PermitUserEnvironment no/' $SSHCHEMIN       # Ne pas permettre le changement des variables d'environnement
            echo -e "\n${vert}[ OK ] - Permettre le changement des variables d'environnement : $(grep -Ei '^PermitUserEnvironment' $SSHCHEMIN | awk -F " " '{print $2}')${neutre}\n" || echo -e "\n${rouge}[ NOK ] - Erreur de PermitUserEnvironment${neutre}\n"
        else
            echo -e "\n${bleufondjaune}[ OK - pas de changement ] - Permettre le changement des variables d'environnement : $(grep -Ei '^PermitUserEnvironment' $SSHCHEMIN | awk -F " " '{print $2}')${neutre}\n"
        fi
        sleep 2
        
        # DCNX du client SSH après 10 minutes d'inactivité
        grep -qE '^(|#|# )ClientAliveInterval 0' $SSHCHEMIN
        if [ "$?" = "0" ] ; then
            sed -i 's/#ClientAliveInterval 0/ClientAliveInterval 600/' $SSHCHEMIN           # DCNX du client SSH après 10 minutes d'inactivité
            echo -e "\n${vert}[ OK ] - Déconnexion du client SSH après X minutes d'inactivité (il faut 10 minutes): $(($(grep -Ei '^ClientAliveInterval' $SSHCHEMIN | awk -F " " '{print $2}')/60)) minutes${neutre}\n" || echo -e "\n${rouge}[ NOK ] - Erreur de ClientAliveInterval${neutre}\n"
        else
            echo -e "\n${bleufondjaune}[ OK - pas de changement ] - Déconnexion du client SSH après X minutes d'inactivité (il faut 10 minutes): $(($(grep -Ei '^ClientAliveInterval' $SSHCHEMIN | awk -F " " '{print $2}')/60)) minutes${neutre}\n"
        fi
        sleep 2
        
        # Type de chiffrement des données (confidantialité)
        grep -qE '^(#|# )Ciphers' $SSHCHEMIN
        if [ "$?" = "0" ] ; then
            sed -i "/^#Ciphers and keying/a Ciphers aes256-ctr,aes192-ctr,aes128-ctr" $SSHCHEMIN     # Type de chiffrement des données (confidantialité) et controle d'integrite prendant la communication (ne jamais utiliser CD MAIS CTR avec SSH car vulnérable dans le cas de ce systeme)
            echo -e "\n${vert}[ OK ] - Type de chiffrement des données (confidantialité) : $(grep -Ei '^Ciphers' $SSHCHEMIN | awk -F " " '{print $2}' | tr "," " ")${neutre}\n" || echo -e "\n${rouge}[ NOK ] - Erreur de Ciphers${neutre}\n"
        else
            echo -e "\n${bleufondjaune}[ OK - pas de changement ] - Type de chiffrement des données (confidantialité) : $(grep -Ei '^Ciphers' $SSHCHEMIN | awk -F " " '{print $2}' | tr "," " ")${neutre}\n"
        fi
        sleep 2
        
        # MAC (Message Authentication Code). Pour la protection de l'authenticité des données
        grep -qE '^(#|# )MACs' $SSHCHEMIN
        if [ "$?" = "0" ] ; then
            sed -i "/^# Ciphers and keying/a MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com" $SSHCHEMIN   # MAC (Message Authentication Code). Pour la protection de l'authenticité des données
            echo -e "\n${vert}[ OK ] - MAC (Message Authentication Code). Pour la protection de l'authenticité des données : $(grep -Ei '^MACs' $SSHCHEMIN | awk -F " " '{print $2}' | tr "," " ")${neutre}\n" || echo -e "\n${rouge}[ NOK ] - Erreur de MACs${neutre}\n"
        else
            echo -e "\n${bleufondjaune}[ OK - pas de changement ] - MAC (Message Authentication Code). Pour la protection de l'authenticité des données : $(grep -Ei '^MACs' $SSHCHEMIN | awk -F " " '{print $2}' | tr "," " ")${neutre}\n"
        fi
        sleep 2
        
        
        # Utilisateur et groupe SSH
        # --------------------------
        while true ; do     
            echo "========================================================================================"
            echo -e "\nQuel utilisateur voulez-vous ajouter au seul groupe autorisé à utiliser le SSH ?\n"       #  seul les utilisateurs du groupe "sshgoupe" sur la machine "IP" sont autorisés à utiliser SSH
            read -p "Entrer le nom d'utilisateur : " entrerUser ;
            grep -Eo "^$entrerUser" /etc/passwd
            if [ "$?" = "0" ] ; then        # si l'utilisateur existe
                grep -Eo "^sshgroupe" /etc/group
                if [ "$?" != "0" ] ; then # si le groupe n'existe pas
                    echo "Le groupe sshgroupe n'existe pas"
                    groupeadd sshgroupe &&  echo -e "${vert}[ OK ] - Création du groupe : sshgroupe ${neutre}"
                    usermod -aG sshgroupe $entrerUser &&  echo -e "${vert}[ OK ] - On met l'utilisateur $entrerUser dans le groupe sshgroupe ${neutre}"
                    grep -q sshgroupe $SSHCHEMIN
                    if [ "$?" != 0 ] ; then # Les lignes suivantes ne sont pas présentes dans sshd_config : donc on les ajoute
                        sed -i '/MaxSessions 2/a AllowGroups sshgroupe' $SSHCHEMIN &&  echo -e "${vert}[ OK ] - Ajout de la chaîne à $SSHCHEMIN : AllowGroups sshgroupe ${neutre}"
                        sed -i "/AllowGroups sshgroupe/a AllowGroups sshgroupe@$IPV4SRV/24" $SSHCHEMIN &&  echo -e "${vert}[ OK ] - Ajout de la chaîne à $SSHCHEMIN : AllowGroups sshgroupe@$IPV4SRV/24 ${neutre}"
                    fi
                    break
                else # si le groupe existe
                    echo "Affiliation au groupe de l'utilisateur : $entrerUser"
                    usermod -aG sshgroupe $entrerUser &&  echo -e "${vert}[ OK ] - On met l'utilisateur $entrerUser dans le groupe sshgroupe ${neutre}"
                    grep -q sshgroupe $SSHCHEMIN
                    if [ "$?" != 0 ] ; then # Les lignes suivantes ne sont pas présentes dans sshd_config : donc on les ajoute
                        sed -i '/MaxSessions 2/a AllowGroups sshgroupe' $SSHCHEMIN &&  echo -e "${vert}[ OK ] - Ajout de la chaîne à $SSHCHEMIN : AllowGroups sshgroupe ${neutre}"
                        sed -i "/AllowGroups sshgroupe/a AllowGroups sshgroupe@$IPV4SRV/24" $SSHCHEMIN &&  echo -e "${vert}[ OK ] - Ajout de la chaîne à $SSHCHEMIN : AllowGroups sshgroupe@$IPV4SRV/24 ${neutre}"
                    fi
                    break
                fi
            else    # Si l'utilisateur n'existe pas
                	echo -e "\n[ ${rouge}NOK${neutre} ] - L'utilisateur \"${violet}$entrerUser${neutre}\" n'existe pas, recommencer.\n"
                	echo -e "${rouge}Retour dans 3 secondes ...\n${neutre}"
                    sleep 3
            fi
        done
                
        # Ajout du port SSH autorisé à SELINUX    
        semanage port -a -t ssh_port_t -p tcp $PORTSSH && echo -e "${vert}[ OK ] - Ajout du port TCP $PORTSSH à SELinux ${neutre}" || echo -e "\n${rouge}[ NOK ] - Erreur de selinux sur le port TCP $PORTSSH ${neutre}\n"
        
        # Ajout du port SSH au firewall
        firewall-cmd --permanent --add-port=$PORTSSH/tcp && echo -e "${vert}[ OK ] - Ajout du port TCP $PORTSSH à firewalld ${neutre}" || echo -e "\n${rouge}[ NOK ] - Erreur de règle firewall sur le port TCP $PORTSSH ${neutre}\n"
        firewall-cmd --reload && echo -e "${vert}[ OK ] - Service Firewall redémarré ${neutre}" || echo -e "\n${rouge}[ NOK ] - Erreur du service firewall ${neutre}\n"
   
        # redémarrage du service SSH
        restartSSH  && echo -e "${vert}[ OK ] - Service SSH redémarré ${neutre}" || echo -e "\n${rouge}[ NOK ] - Erreur du service SSH ${neutre}\n"
   
   }
    

    
    #--------------------------------------------------



########    MENU    ########    MENU    ########    MENU    ########    MENU    ######## 

clear
while true ; do

    echo -e "${vert}                   ______        ______        ______                      ${neutre}"
    echo -e "${vert}                  /_____/\      /_____/\      /_____/\                     ${neutre}"
    echo -e "${vert}     _______      \:::_ \ \     \::::_\/_     \:::_ \ \          _______   ${neutre}"
    echo -e "${vert}    /______/\      \:\ \ \ \     \:\/___/\     \:(_) ) )_       /______/\  ${neutre}"
    echo -e "${vert}    \__::::\/       \:\ \ \ \     \_::._\:\     \: __ \`\ \      \__::::\/ ${neutre}"
    echo -e "${vert}                     \:\_\ \ \      /____\:\     \ \ \`\ \ \               ${neutre}"
    echo -e "${vert}                      \_____\/      \_____\/      \_\/ \_\/                ${neutre}"
    echo " "
    echo -e "${rouge}            -- [ OUTILS DE SECURISATION REDHAT ] --${neutre}"
    echo " "
    echo -e "${bleu}Faites votre choix de configuration :${neutre}"
    echo -e "${vert}-----------------------------------${neutre}"
    echo -e "[  ${bleu}1${neutre} ] - Configurer les paramètres réseaux"
    echo -e "[  ${bleu}2${neutre} ] - Mise à jour de l'OS"
    echo -e "[  ${bleu}3${neutre} ] - Désactiver IPv6"
    echo -e "[  ${bleu}4${neutre} ] - Modifier le nom de machine"
    echo -e "[  ${bleu}5${neutre} ] - Sécurisation du GRUB 2"
    echo -e "[  ${bleu}6${neutre} ] - Sécurisation SeLinux"
    echo -e "[  ${bleu}7${neutre} ] - Sécurisation SSH"
    echo -e "[ ${violet}10${neutre} ] - Tout installer"
    echo
    #echo -e "[  ${rouge}F${neutre} ] - Taper F pour finaliser l'installation..."
    #echo -e "        ---> Dans tous les cas, une fois vos installations choisies, terminer par l'option [ F ]\n"
    #echo
    echo -e "${rouge}[  Q ] - Taper Q pour quitter...${neutre}\n"
    read -p "Entrer votre choix : " choixmenu ;
    echo

    case $choixmenu in
    "1")
        modifIpMaskGw ; restartRZO ; testINTERNET ;;
    "2")
        MAJOS ;;
    "3")
        desactivIPV6 ;;
    "4")
        modifHOSTNAME ;;
    "5")
        secuGRUB2 ;;
    "6")
        seLINUX ;;
    "7")
        secuSSH ;;
    "10")
         modifIpMaskGw ; restartRZO ; testINTERNET ; MAJOS ; desactivIPV6 ; modifHOSTNAME ; secuGRUB2 ; seLINUX ; secuSSH ;;
    f|F) break ;;
    q|Q) exit ;;
    *) continue ;;
    esac     
done











































