# Go Http socket proxy

Ce projet *exemple* se base sur le code de [sparrc](https://github.com/sparrc/go-ping). Chaque appel à la commande ping réalise un ping unique, contrairement à celui de sparrc. Il appartient à l'appelant d'encapsuler son ping dans une go routine.

Je l'utilise pour palier à des instabilités de la librairie 'net-ping' pour nodejs (En effet, 'raw-socket' sur lequel se base 'net-ping' s'installe directement dans la boucle principale. Dans certaines circonstances d'utilisation de 'net-ping', la boucle principale de nodejs se plantait lamentablement.).

Il est prévu d'implémenter d'autres requêtes raw socket (UDP, TCP, ...) seulement si j'en ai besoin dans mes projets annexes (donc peut-être un jour :-/ ).

## Comment ça marche ?
Lancer la commande 'socketproxy' ou 'socketproxy.exe' comme suit :
```bash
./socketproxy [-h localhost] [-p 9797] [-privileged]
#	-h to define host instead of 'localhost'
#	-p to define port superior to 1024 instead of '9797'
#	-privileged to activate privileged ping mode'
```

Il est possible de l'embarquer dans un projet node comme suit :
```javascript
// TODO
```

socketproxy écoute par défaut sur le port 9797 et fournit le microservice suivant:

#### ping?timeout=2s&ip=192.168.XXX.XXX

|Paramètre|Description
|----     |-----
|timeout  |Respecter la syntaxe définie ici : https://golang.org/pkg/time/#ParseDuration
|ip       |L'ip vers lequel lancer un ping



<table>
<thead>
<tr><th>Description</th><th>Code</th></tr>
</thead>
<tbody>
<tr>
<td>La valeur de retour :</td>
<td>{"result":true,"ip":"216.58.213.131","time":58620926,"timeout":false,"error":""}<br/>Time s'exprime en nanosecondes</td>
</tr>
<tr>
<td>La valeur de retour en cas d'erreur : </td>
<td>{"result":false,"ip":"xxx.xxx.xxx.xxx","time":0,"timeout":true,"error":"intitulé de l'erreur"}</td>
</tr>
<tr>
<td>La valeur de retour en cas d'erreur du mode privilégié : </td>
<td>{"result":false,"ip":"xxx.xxx.xxx.xxx","time":0,"Error":"No packet"}</td>
</tr>
</tbody>
</table>

## A veiller !
* Le repo principal n'est pas github. En récupérant les sources, assurez-vous donc de modifier le chemin du package vers pingutils.go dans le fichier cmd/main.go
