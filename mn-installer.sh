#!/bin/bash
#
# BCE Masternode Install Script to be run on Ubuntu and similar linux

# Project Name
PROJECT=blockchainenergy
PORT=18049

# Project Name uppercase
PROJ_U=${PROJECT^^}

GITHUB_REPO="blockchainenergy-project/"${PROJ_U}"-core"
GITHUB_URL="https://github.com/"$GITHUB_REPO

RELEASE_URL=$(curl -Ls -o /dev/null -w %{url_effective} $GITHUB_URL/releases/latest)
RELASE_TAG="${RELEASE_URL##*/}"
VERSION="${RELASE_TAG##$V}"

LOGFILENAME=$PROJECT"-mn-install.log"

# Wallet (daemon) link
WALLETLINK=$GITHUB_URL"/releases/download/V"$VERSION"/daemon18.04.tar.gz"


DATADIRNAME="."$PROJECT											#datadir name
DAEMONFILE=$PROJECT"d"											#daemon file name
CLIFILE=$PROJECT"-cli"											#cli file name
CONF_FILE=$PROJECT".conf"										#conf file name
SERVICEFILE="/etc/systemd/system/"${PROJ_U}".service"			#service file name

function init_gui_vars() {
# Defining colors for console
	NC="\033[0m" # Text Reset
	#Start bold text;	#Start NO bold text;	
	ColrBld="\e[1m";	ColrNoBld="\e[21m";
	ITA="\033[3m"
	RED="\033[0;31m"
	GREEN="\033[0;32m"
	YELLOW="\033[0;33m"                     ColrYelBld="\e[1;33m";
	BLUE="\033[0;34m"
	PURPLE="\033[0;35m"
	CYAN="\033[0;36m";	ColrCya="\e[0;36m";	ColrCyaBld="\e[1;36m";	ColrCyaItl="\e[3;36m";	ColrCyaUnd="\e[4;36m";
	WHITE="\033[0;37m"

# main procedure
    cols=$(tput cols)
    if [ $cols -ge 100 ]; then cols=100; fi
    mv=$(expr $cols - 13)
    STATUSX="\033[${mv}C "
    STATUS0="\033[${mv}C [${GREEN}  DONE  ${NC} ]\n" #[  DONE  ]
    STATUS1="\033[${mv}C [${RED} FAILED ${NC}]\n"    #[ FAILED ]
    STATUS2="\033[${mv}C [${YELLOW}  SKIP  ${NC}]\n" #[  SKIP  ]
	WS="          "
}

function print_welcome() {
    echo -e "  This script is for fresh installed Ubuntu.\n It will install ${PROJ_U} masternode, version ${VERSION}\n"
    echo -e "  ${RED}WARNING: Running this script will overwrite existing installation!${NC}\n"
    read -n1 -p " Press any key to continue or CTRL+C to exit ... " confirmtxt
    echo -e "  Starting new installation now...\n\n"
}

function install_updates() {
	echo -e "* Package installation"
    apt-get -o=Dpkg::Use-Pty=0 -o=Acquire::ForceIPv4=true update 	
    apt-get -y -o=Dpkg::Use-Pty=0 -o=Acquire::ForceIPv4=true install dirmngr wget software-properties-common
    add-apt-repository -yu ppa:bitcoin/bitcoin 
    apt-get -o=Dpkg::Use-Pty=0 -o=Acquire::ForceIPv4=true update 
    apt-get -y -o=Dpkg::Use-Pty=0 -o=Acquire::ForceIPv4=true install build-essential \
    libboost-all-dev autotools-dev automake libssl-dev libcurl4-openssl-dev \
    libboost-all-dev make autoconf libtool git apt-utils g++ libzmq3-dev libminiupnpc-dev\
    libprotobuf-dev pkg-config libcurl3-dev libudev-dev libqrencode-dev bsdmainutils \
    pkg-config libssl-dev libgmp3-dev libevent-dev python-virtualenv virtualenv libdb4.8-dev libdb4.8++-dev
	echo -en "Installing system updates/upgrades finished \r"$STATUS0
}

function install_firewall() {
	echo -n "Do you want to install all needed firewall settings (no - only if you did it before)? [y/n]: "
	read -n1 ANSWER
	if [[ ${ANSWER} =~ ^[nN] ]] ; then
		return 0;
	fi
	echo "";
	sudo apt-get install ufw -qq 
	sudo ufw allow ssh/tcp  
	sudo ufw limit ssh/tcp
	sudo ufw logging on
	sudo ufw allow 22
	sudo ufw allow ${PORT}
	echo "y" | sudo ufw enable
	sudo ufw status
	echo -en "Installing firewall settings \r"$STATUS0
}

function download_mn_wallet(){
	WALLETFILENAME="${WALLETLINK##*/}"
	echo -en "\n Downloading wallet ${WALLETFILENAME} \r"
	cd ~ && wget -q $WALLETLINK
	[ $? -eq 0 ] && ec=0 || ec=1
	[ $ec -eq 0 ] && echo -en $STATUS0 || echo -en $STATUS1
}

function unzip_mn_wallet(){
	echo -en " Unzippinging the wallet \r"
	tar -xvzf $WALLETFILENAME > /dev/null
	[ $? -eq 0 ] && ec=0 || ec=1
	[ $ec -eq 0 ] && echo -en $STATUS0 || echo -en $STATUS1
	
	#delete wallet ZIP file
	echo -en " Deleting the file $WALLETFILENAME \r"
	rm $WALLETFILENAME > /dev/null
	[ $? -eq 0 ] && ec=0 || ec=1
	[ $ec -eq 0 ] && echo -en $STATUS0 || echo -en $STATUS1
}

# Help function to show progress while downloading file
function progressfilt (){
    local flag=false c count cr=$'\r' nl=$'\n'
    while IFS='' read -d '' -rn 1 c
    do
        if $flag
        then
            printf '%s' "$c"
        else
            if [[ $c != $cr && $c != $nl ]]
            then
                count=0
            else
                ((count++))
                if ((count > 1))
                then
                    flag=true
                fi
            fi
        fi
    done
}


# Get this server IP
function get_ip(){
	IP=$(hostname -I | cut -d " " -f1)
	echo -en " Your IP is ${ColrCyaBld}${IP}${NC} correct? [y]/n: "
	read -n1 ANSWER
	if [[ ${ANSWER} =~ ^[nN] ]] ; then
		echo -en "\n Enter your IP: "
		read IP
		#Regex for number 0-255
		REG_255="(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"
		IP_REGEX=^$REG_255\.$REG_255\.$REG_255\.$REG_255$
		while [[ ! ${IP} =~ $IP_REGEX ]]
		do
			echo -en " ${RED}Wring IP!${NC}\n Enter correct IPv4 address: "
			read IP
		done
	fi
	echo -e " IP: ${ColrCyaBld}${IP}${NC} will be used"
}

# This config file is used just to start deamon as a simple node, but not Masternode.
function get_empty_config_file_text(){
	local txt2ret="rpcuser=user"`shuf -i 100000-10000000 -n 1`
	txt2ret+="\nrpcpassword=passw"`shuf -i 100000-10000000 -n 1`
	txt2ret+="\nrpcallowip=127.0.0.1"
	txt2ret+="\nserver=1"
	txt2ret+="\ndaemon=1"
	txt2ret+="\nlogtimestamps=1"
	txt2ret+="\nmaxconnections=256"
	txt2ret+="\nexternalip=${IP}"
	echo $txt2ret
}

# Run server temporary to be able to get PRIVATE_KEY
function run_empty_server(){
	get_ip
	
	local config_file_text=$(get_empty_config_file_text)
	
	#Change directiory to the DATA FOLDER
	mkdir -p ${DATADIRNAME}
	
	echo -en " Writing config file for empty server \r"
	echo -e $config_file_text > ${DATADIRNAME}/$CONF_FILE
	[ $? -eq 0 ] && ec=0 || ec=1
	[ $ec -eq 0 ] && echo -en $STATUS0 || echo -en $STATUS1
	
	#run server
	echo -e " Start empty server \r"
	./$DAEMONFILE -daemon  > /dev/null 2>&1
	[ $? -eq 0 ] && ec=0 || ec=1
	[ $ec -eq 0 ] && echo -en $STATUS0 || echo -en $STATUS1
	sleep 3
}

# Generates PRIVATE_KEY by temporary server
function generate_priv_key(){
	echo -en " Creating new masternode private key \r"
	PRIVATE_KEY=$(./${CLIFILE} masternode genkey)
	if [ $? -gt 0 ]; then
		echo -en $STATUS1
		return 1
	fi
	echo -en $STATUS0
	echo -e " Created the private key: ${ColrCyaBld}${PRIVATE_KEY}${NC}"
	return 0
}

# Gets PRIVATE_KEY from user in case failed to get PRIVATE_KEY from server
function get_priv_key_from_user(){
	echo -e "Failed to gererate private key.\n"
	echo -e "You can get private key in QTWallet => Tools => Debug Console, then run command \"masternode genkey\"\nInsert the new Masternoe Key: "
	read PRIVATE_KEY
	if [ ${#PRIVATE_KEY} -eq 51 ]; then
		return 0
	fi
	echo -e "The private key length is wrong\nPlease update the config file later manually"
	return 1
}

# This config file is used just to start deamon as a simple node, but not Masternode.
function get_mastenode_config_file_text(){
	CONF_FILE_TEXT=$(get_empty_config_file_text)
	PRIVATE_KEY=""
	generate_priv_key
	if [ $? -eq 1 ]; then
        get_priv_key_from_user
	fi
	
	CONF_FILE_TEXT+="\nmasternode=1"
	CONF_FILE_TEXT+="\nmasternodeprivkey=${PRIVATE_KEY}"
}

# Run full/final server
function run_full_server(){
	get_mastenode_config_file_text
	echo -e " Stop the server \n"
	./${CLIFILE} stop > /dev/null 2>&1
	[ $? -eq 0 ] && ec=0 || ec=1
	[ $ec -eq 0 ] && echo -en $STATUS0 || echo -en $STATUS1
	
	echo -en " Writing full config file \r"
	echo -e $CONF_FILE_TEXT > ${DATADIRNAME}/$CONF_FILE
	[ $? -eq 0 ] && ec=0 || ec=1
	[ $ec -eq 0 ] && echo -en $STATUS0 || echo -en $STATUS1
}

# This config file for the service
function service_get_config_file_text(){
	USER_DIR=$(pwd)
	SERV_PARAMS=" -conf=${USER_DIR}/.${PROJECT}/${PROJECT}.conf -datadir=${USER_DIR}/.${PROJECT}/ "
	local txt2ret="[Unit]"
	txt2ret+="\nDescription=${PROJ_U} service"
	txt2ret+="\nAfter=network.target"
	txt2ret+="\n[Service]"
	txt2ret+="\nUser=root"
	txt2ret+="\nGroup=root"
	txt2ret+="\nType=forking"
	txt2ret+="\nExecStart=${USER_DIR}/${DAEMONFILE} -daemon ${SERV_PARAMS}"
	txt2ret+="\nExecStop=${USER_DIR}/${CLIFILE} stop"
	txt2ret+="\nRestart=always"
	txt2ret+="\nPrivateTmp=true"
	txt2ret+="\nTimeoutStopSec=60s"
	txt2ret+="\nTimeoutStartSec=10s"
	txt2ret+="\nStartLimitInterval=120s"
	txt2ret+="\nStartLimitBurst=5"
	txt2ret+="\n[Install]"
	txt2ret+="\nWantedBy=multi-user.target"
	echo $txt2ret
}

# Write service config file to services folder
function service_create_config_file(){
	local config_file_text=$(service_get_config_file_text)
	echo -en " Creating service file \r"
	echo -e $config_file_text > $SERVICEFILE
}

# Make the new service auto-start 
function service_start_autostart(){
	echo -en " Starting ${PROJ_U}.service \r"
	systemctl start ${PROJ_U}.service > /dev/null 2>&1
	[ $? -eq 0 ] && ec=0 || ec=1
	[ $ec -eq 0 ] && echo -en $STATUS0 || echo -en $STATUS1
	sleep 3
	echo -en " Enabling ${PROJ_U}.service \r"
	systemctl enable ${PROJ_U}.service > /dev/null 2>&1
	[ $? -eq 0 ] && ec=0 || ec=1
	[ $ec -eq 0 ] && echo -en $STATUS0 || echo -en $STATUS1
	sleep 3
}

# Check service started
function show_service_status(){
	echo -en " Check service status: \r"
	systemctl is-active --quiet ${PROJ_U}.service
	[ $? -eq 0 ] && ec=0 || ec=1
	[ $ec -eq 0 ] && echo -en $STATUS0 || echo -en $STATUS1
}

#synchronizing with blockchain
function wait_finish_synchronizing_with_blockchain(){
	local SYNCD=""
	local CURR_BLK=""
	
	while true; do
		SYNCD=$(./${CLIFILE} mnsync status | grep IsBlockchainSynced | grep -oE '(true|false)')
		CURR_BLK=$(./${CLIFILE} getinfo | grep blocks | grep -oE '[0-9]*')
		if [[ "${SYNCD}" == "true" ]]; then
			echo -en " Blocks synchronizing, last block ${ColrCya}${CURR_BLK}${NC}${WS}\r"$STATUS0
			break;
		fi
		echo -en " Synchronizing blocks: current block ${ColrCya}${CURR_BLK}${NC}     \r"
		sleep 3
	done
	
	while true; do
		SYNCD=$(./${CLIFILE} mnsync status | grep RequestedMasternodeAssets | grep -oE '[0-9]*' )
		if [[ $SYNCD -eq 999 ]]; then
			echo -en " Finished masternode synchronization${WS}${WS}${WS}\r"$STATUS0
			break
		fi
		echo -en " Waiting for masternode synchronization: MasternodeAssets=${SYNCD}     \r"
		sleep 5
	done
}

# Get INDEX for TXID (transaction id)
function get_txid_index(){
	local tmp_val=$(./${CLIFILE} getrawtransaction $TXID 2>/dev/null )
	[ $? -eq 0 ] && ec=0 || ec=1
	if [[ ${tmp_val} == "" || $ec -eq 1 ]]; then
		echo -e " This TXID doesn't exist yet"
		while true; do
			SYNCD=$(./${CLIFILE} mnsync status 2>/dev/null | grep IsBlockchainSynced 2>/dev/null | grep -oE '(true|false)' 2>/dev/null )
			CURR_BLK=$(./${CLIFILE} getinfo 2>/dev/null | grep blocks | grep -oE '[0-9]*' )
			tmp_val=$(./${CLIFILE} getrawtransaction $TXID 2>/dev/null )
			if [ ${SYNCD} == "true" ]; then
				echo -e "\n Finished synchronizing blockchain, last block ${ColrCya}${CURR_BLK}${NC}  \r";
				echo -e $STATUS0
				break;
			fi
			echo -en " Wait for synchronizing blocks:  current block ${CURR_BLK}       \r"
			sleep 3
		done
	fi
	tmp_val=$(./${CLIFILE} getrawtransaction $TXID 2>/dev/null )
	[ $? -eq 0 ] && ec=0 || ec=1
	if [[ ${tmp_val} == "" || $ec -eq 1 ]] ; then
		return 1
	fi
	INDEX=$(./${CLIFILE} decoderawtransaction $tmp_val  | pcregrep -M '"vout": \[(\n|.)*value*(\n|.)*value*(\n|.)*addresses' | pcregrep -M '"value": [1,5,20,100]000000.00000000,\n(\n|.)*"scriptPubKey"' | grep '"n"' | grep -o -E '[0-9]+' | head -1)
	if [[ $INDEX -ne 1 && $INDEX -ne 0 ]] ; then
		return 1
	fi
	return 0
}

# Helps user to configure MN on Wallet
function help_configure_user_masternode_conf_file(){
	echo -en " Setup this MasterNode in your wallet \"masternode.conf\"...\n Enter MasterNode name: "
	read MN_NAME
	while [ ${#MN_NAME} -eq 0 ]; do
		echo -e " ${RED} The name can't be empty string!${NC}\n Please provide a name for this MasterNode: "
		read MN_NAME
	done
	
	#Regex
	TXID_REGEX="^[a-fA-F0-9]{64}$"
	while true
	do
		echo -en " Enter transaction ${ColrCya}TXID${NC}: "
		read TXID
		[[ ${TXID} =~ $TXID_REGEX ]] && break
		echo -e "${RED} TXID shall be 64 hecadecimals!${NC}"
	done
	INDEX=-1
	get_txid_index
	if [ $? -eq 1 ]; then
        echo -e " ${RED}This TXID was not found in the blockchain after synchronization${NC}"
		read -p " Are you sure you want to continue configure your local wallet y/[n]?" -n 1 -r
		echo    # (optional) move to a new line
		if [[ ! $REPLY =~ ^[Yy]$ ]]
		then
			return 1
		fi
	fi
	
	if [[ $INDEX -ne 1 && $INDEX -ne 0 ]] ; then
		echo -en "\n Enter ${ColrCya}INDEX${NC} of the transaction: "
		read INDEX
	fi

	echo -e " Copy next row to the end of your wallet \"masternode.conf\" file:"
	echo -e "${ColrCya} ${MN_NAME} ${IP}:${PORT} $PRIVATE_KEY $TXID $INDEX${NC}\n\n"
	read -n 1 -s -r -p "Press any key to continue"
	return 0
}

function print_devsupport_exit() {
	echo -e "\n===================================================================================="
	echo -e "\n Thank you for using this script.\n Done\n Exiting now..."
    exit 0
}


# 0. 
	init_gui_vars
# 1. Welcome screen
	print_welcome
# 2. Install Updates and Firewall
	install_updates
	install_firewall
# 3. download new daemon & unzip & delete file in the end
	download_mn_wallet
	unzip_mn_wallet
# 5.Run empty server to be able to get new private key, then edit the config file, then run full MN
	run_empty_server
	run_full_server
# 6.Create service: create file, enable & start service, show status
	service_create_config_file
	service_start_autostart
	show_service_status
# 7. Finish Synchronizing
	wait_finish_synchronizing_with_blockchain
# 8.Configure the MN in user's wallet
	help_configure_user_masternode_conf_file
# 9.Finish
	print_devsupport_exit
