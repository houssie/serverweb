<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <title>Test Proxy - Backend <?php echo getenv('SERVER_ADDR') ?: ($_SERVER['SERVER_ADDR'])?></title>
</head>
<body>
    <h1>Test du Serveur Proxy Reverse</h1>
    <p>Backend actuel : <?php echo getenv('SERVER_ADDR') ?: ($_SERVER['SERVER_ADDR']); ?></p>
    <p>Heure du serveur : <?php echo date('Y-m-d H:i:s'); ?></p>
    <p>IP client : <?php  echo getenv('SERVER_ADDR')?></p>
    <p>Cette page est servie par un backend avec PHP.</p>
    <p>Rafraîchissez pour voir l'alternance via le load balancing.</p>
</body>
</html>