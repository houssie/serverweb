<?php
header('Content-Type: text/html; charset=utf-8');
?>
<!DOCTYPE html>
<html>
<head><title>PHP Test</title></head>
<body>
    <h1>Test d'exécution PHP</h1>
    <p>Serveur backend : <?php echo $_SERVER['SERVER_ADDR'] ?? '127.0.0.1'; ?></p>
    <p>Port : <?php echo $_SERVER['SERVER_PORT'] ?? '8081'; ?></p>
    <p>Heure PHP : <?php echo date('H:i:s'); ?></p>
    <p>Heure système : <span id="time"></span></p>
    <p><a href="/">Retour</a></p>
    
    <script>
        document.getElementById('time').textContent = new Date().toLocaleString();
    </script>
</body>
</html>