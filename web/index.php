<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <title>Test Proxy - Backend <?php echo (isset($_SERVER['SERVER_ADDR']) ? $_SERVER['SERVER_ADDR'] : '127.0.0.1') . ':' . (isset($_SERVER['SERVER_PORT']) ? $_SERVER['SERVER_PORT'] : '8081'); ?></title>
</head>
<body>
    <h1>Test du Serveur Proxy Reverse</h1>
    <p>Backend actuel : <?php echo (isset($_SERVER['SERVER_ADDR']) ? $_SERVER['SERVER_ADDR'] : '127.0.0.1') . ':' . (isset($_SERVER['SERVER_PORT']) ? $_SERVER['SERVER_PORT'] : '8081'); ?></p>
    <p>Heure du serveur : <?php echo date('Y-m-d H:i:s'); ?></p>
    <p>IP client : <?php echo isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : '127.0.0.1'; ?></p>
    <p>Cette page est servie par un backend avec PHP.</p>
    <p>Rafraîchissez pour voir l'alternance via le load balancing.</p>
</body>
</html>