<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Détails du produit</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f4f4f4;
        }
        .container {
            max-width: 1000px;
            margin: 0 auto;
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        .back-link {
            display: inline-block;
            margin-bottom: 20px;
            padding: 10px 15px;
            background: #3498db;
            color: white;
            text-decoration: none;
            border-radius: 5px;
        }
        .back-link:hover {
            background: #2980b9;
        }
        .product-detail {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 40px;
            align-items: start;
        }
        .product-image {
            width: 100%;
            border-radius: 8px;
        }
        .product-info {
            padding: 20px;
        }
        .promotion {
            background: #e74c3c;
            color: white;
            padding: 8px 15px;
            border-radius: 4px;
            font-weight: bold;
            display: inline-block;
            margin-bottom: 15px;
        }
        .product-name {
            font-size: 28px;
            color: #2c3e50;
            margin-bottom: 15px;
        }
        .product-category {
            background: #f39c12;
            color: white;
            padding: 5px 10px;
            border-radius: 3px;
            text-decoration: none;
            display: inline-block;
            margin-bottom: 15px;
        }
        .product-unite {
            color: #7f8c8d;
            font-size: 16px;
            margin-bottom: 20px;
        }
        .prices {
            display: flex;
            align-items: center;
            gap: 15px;
            margin-bottom: 20px;
        }
        .original-price {
            text-decoration: line-through;
            color: #7f8c8d;
            font-size: 18px;
        }
        .current-price {
            color: #e74c3c;
            font-size: 32px;
            font-weight: bold;
        }
        .add-to-cart {
            padding: 15px 30px;
            background: #27ae60;
            color: white;
            border: none;
            border-radius: 5px;
            font-size: 18px;
            cursor: pointer;
            transition: background 0.3s ease;
            width: 100%;
        }
        .add-to-cart:hover {
            background: #219a52;
        }
        .product-description {
            margin-top: 20px;
            padding: 15px;
            background: #f8f9fa;
            border-radius: 5px;
        }
    </style>
</head>
<body>
    <div class="container">
        <a href="index.php" class="back-link">← Retour à tous les produits</a>
                
        
        <?php
        require_once 'config.php';
        
        if (isset($_GET['id'])) {
            $product_id = $_GET['id'];
            
            try {
                $query = "SELECT p.*, c.nom as category_name 
                         FROM produits p 
                         JOIN category c ON p.category_id = c.id 
                         WHERE p.id = ?";
                $stmt = $db->prepare($query);
                $stmt->execute([$product_id]);
                $produit = $stmt->fetch(PDO::FETCH_ASSOC);
                
                if ($produit) {
                    echo '<div class="product-detail">';
                    
                    // Image du produit
                    echo '<div>';
                    echo '<img src="images/' . htmlspecialchars($produit['image']) . '" alt="' . htmlspecialchars($produit['nom']) . '" class="product-image">';
                    echo '</div>';
                    
                    // Informations du produit
                    echo '<div class="product-info">';
                    
                    // Promotion
                    if ($produit['promotion'] > 0) {
                        echo '<span class="promotion">-' . $produit['promotion'] . '%</span>';
                    }
                    
                    // Nom
                    echo '<h1 class="product-name">' . htmlspecialchars($produit['nom']) . '</h1>';
                    
                    // Catégorie
                    echo '<a href="categorie.php?id=' . $produit['category_id'] . '&nom=' . urlencode($produit['category_name']) . '" class="product-category">';
                    echo htmlspecialchars($produit['category_name']);
                    echo '</a>';
                    
                    // Unité
                    echo '<p class="product-unite">' . htmlspecialchars($produit['unite']) . '</p>';
                    
                    // Prix
                    echo '<div class="prices">';
                    if ($produit['promotion'] > 0) {
                        echo '<span class="original-price">' . number_format($produit['prix_original'], 2) . ' $</span>';
                    }
                    echo '<span class="current-price">' . number_format($produit['prix'], 2) . ' $</span>';
                    echo '</div>';
                    
                    // Bouton Ajouter au panier
                    echo '<button class="add-to-cart" onclick="addToCart(' . $produit['id'] . ')">';
                    echo '🛒 Ajouter au panier';
                    echo '</button>';
                    
                    // Description
                    if (!empty($produit['description'])) {
                        echo '<div class="product-description">';
                        echo '<h3>Description</h3>';
                        echo '<p>' . htmlspecialchars($produit['description']) . '</p>';
                        echo '</div>';
                    }
                    
                    echo '</div>';
                    echo '</div>';
                } else {
                    echo '<div style="text-align: center; padding: 40px; color: #e74c3c;">';
                    echo '❌ Produit non trouvé';
                    echo '</div>';
                }
                
            } catch(PDOException $e) {
                echo '<div style="background: #e74c3c; color: white; padding: 15px; border-radius: 5px; text-align: center;">';
                echo '❌ Erreur de base de données: ' . $e->getMessage();
                echo '</div>';
            }
        } else {
            echo '<div style="background: #e74c3c; color: white; padding: 15px; border-radius: 5px; text-align: center;">';
            echo '❌ Produit non spécifié';
            echo '</div>';
        }
        ?>
    </div>

    <script>
        function addToCart(productId) {
            alert('Produit ' + productId + ' ajouté au panier !');
        }
    </script>
</body>
</html>