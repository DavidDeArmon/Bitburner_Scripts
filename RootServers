/** @param {NS} ns */
//Look through servers to open ports and gain root access automatically.
export async function main(ns) {
	function findServers() {
		//build list of all servers.
		let serverList = ns.scan(ns.getHostname());
		for (let i = 0; i < serverList.length; i++) {
			let down1list = ns.scan(serverList[i]);
			for (let k = 0; k < down1list.length; k++) {
				if (!serverList.includes(down1list[k])) serverList.push(down1list[k]);
			}
		}
		return serverList;
	}
  
	let fullServerList = findServers();
	let rootedServers = [];
	//loop through server list and open ports then nuke to gain root access.
	for (let i = 0; i < fullServerList.length; i++) {
		let target = fullServerList[i];
		let portsRequired = ns.getServerNumPortsRequired(fullServerList[i])
		let openPorts = 0;
		if (portsRequired > 0) {
			if (ns.fileExists("BruteSSH.exe", "home")) ns.brutessh(target);
			if (ns.fileExists("FTPCrack.exe", "home")) ns.ftpcrack(target);
			if (ns.fileExists("RelaySMTP.exe", "home")) ns.relaysmtp(target);
			if (ns.fileExists("HTTPWorm.exe", "home")) ns.httpworm(target);
			if (ns.fileExists("SQLInject.exe", "home")) ns.sqlinject(target);
			let serverInfo = ns.getServer(fullServerList[i]);
			if (serverInfo.sshPortOpen) openPorts++;
			if (serverInfo.ftpPortOpen) openPorts++;
			if (serverInfo.smtpPortOpen) openPorts++;
			if (serverInfo.httpPortOpen) openPorts++;
			if (serverInfo.sqlPortOpen) openPorts++;
		}
		if (!ns.hasRootAccess(target) && openPorts >= portsRequired) {
			ns.nuke(target);
			rootedServers.push(target);
		}
	}
	ns.tprint(rootedServers)
	return rootedServers;
}
