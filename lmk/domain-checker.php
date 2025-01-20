<?php
// Path to the SQLite database
$dbPath = __DIR__ . '/db/LMK4Scam_Whitelist.sqlite';
$message = '';
$resultMessage = '';

// Blacklist URLs
$blacklistUrl1 = 'https://raw.githubusercontent.com/romainmarcoux/malicious-domains/refs/heads/main/full-domains-aa.txt';
$blacklistUrl2 = 'https://raw.githubusercontent.com/romainmarcoux/malicious-domains/refs/heads/main/full-domains-ab.txt';

// Function to fetch and process blacklist data
function fetchBlacklist($url) {
    $data = @file_get_contents($url); // Suppress warnings if the URL is unreachable
    if ($data === false) {
        throw new Exception("Failed to fetch blacklist from: $url");
    }
    return array_map('trim', explode("\n", $data)); // Return array of trimmed lines
}

try {
    // Connect to the SQLite database
    $pdo = new PDO("sqlite:$dbPath");
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

    // Fetch all domains (TLDs) from the whitelist database
    $stmt = $pdo->query("SELECT domain FROM whitelist");
    $whitelistedTLDs = $stmt->fetchAll(PDO::FETCH_COLUMN);

    // Check if the form has been submitted
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        $inputDomain = $_POST['inputField'] ?? '';
        $tld = strtolower(pathinfo($inputDomain, PATHINFO_EXTENSION));

        // Convert IDN domains to ASCII if necessary
        if (function_exists('idn_to_ascii')) {
            $inputDomain = idn_to_ascii($inputDomain, IDNA_DEFAULT, INTL_IDNA_VARIANT_UTS46);
        }

        // Check if the TLD is in the whitelist
        if (in_array($tld, $whitelistedTLDs)) {
            // TLD is whitelisted, now check the input domain against blacklists
            try {
                $blacklist1 = fetchBlacklist($blacklistUrl1);
                $blacklist2 = fetchBlacklist($blacklistUrl2);

                // Merge blacklists and remove empty lines
                $blacklist = array_filter(array_merge($blacklist1, $blacklist2));

                if (in_array($inputDomain, $blacklist)) {
                    $resultMessage = "Die Domain <strong>$inputDomain</strong> ist blacklisted. Vorsicht!";
                } else {
                    $resultMessage = "Die Domain <strong>.$tld</strong> ist whitelisted und nicht blacklisted. Überlege genau ob es vertrauenswürdig wirkt und handle mit entsprechender Vorsicht.";
                }
            } catch (Exception $e) {
                $message = $e->getMessage();
            }
        } else {
            // TLD is not whitelisted
            $resultMessage = "Die TLD <strong>$tld</strong> ist weder whitelisted noch blacklisted. Sie stammt aus einer unbekannten Quelle. Vorsicht!";
        }
    }
} catch (PDOException $e) {
    $message = "Failed to connect to the database: " . $e->getMessage();
}
?>

<!DOCTYPE html>
<html data-bs-theme="light" lang="en">

<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, shrink-to-fit=no">
    <title>Domain-Checker</title>
    <link rel="stylesheet" href="assets/bootstrap/css/bootstrap.min.css">
    <link rel="stylesheet" href="https://fonts.googleapis.com/css?family=Inter:300italic,400italic,600italic,700italic,800italic,400,300,600,700,800&amp;display=swap">
    <link rel="stylesheet" href="https://fonts.googleapis.com/css?family=Poppins:400,500,600,700&amp;display=swap">
</head>

<body style="background: #fbf9f2;font-family: Poppins, sans-serif;">
    <nav class="navbar navbar-expand-md sticky-top navbar-shrink py-3" id="mainNav" style="background: rgb(126,213,184);">
        <div class="container">
        <img width="60" height="35" src="assets/img/logo.png" style="margin-right: 14px;"  style="width: 84px;height: 52px;padding: 0px;">
            <a class="navbar-brand d-flex align-items-start" href="index.html"><span class="d-flex align-items-start align-content-start" style="padding-left: 15px;">LMK4Scam</span></a>
            <div class="collapse navbar-collapse" id="navcol-1">
                <ul class="navbar-nav mx-auto">
                    <li class="nav-item"><a class="nav-link" href="index.html">Home</a></li>
                    <li class="nav-item"><a class="nav-link" href="meme-gallerie.html">Meme-Galerie</a></li>
                    <li class="nav-item"><a class="nav-link" href="vergleich.html">Vergleiche</a></li>
                    <li class="nav-item"><a class="nav-link active" href="domain-checker.php">Domain-Checker</a></li>
                    <li class="nav-item"><a class="nav-link" href="impressum.html">Impressum</a></li>
                </ul>
                <div class="dropdown show">
                    <a class="dropdown-toggle" aria-expanded="true" data-bs-toggle="dropdown" href="#" style="margin-right: 55px;">Suche</a>
                        <div class="dropdown-menu show" data-bs-popper="none" style="margin-top: 24px;border-radius: 0px;">
                            <a class="dropdown-item" href="meme-gallerie.html#memes">Memes</a>
                            <a class="dropdown-item" href="vergleich.html#mails">Mails Vergleiche</a>
                            <a class="dropdown-item" href="vergleich.html#sms">SMS Vergleiche</a>
                        </div>
                </div>
            </div>
        </div>
    </nav>
    <div class="alert alert-success" role="alert" style="border-radius: 0px;border-style: none;background: rgb(241,206,204);color: rgb(73,4,0);"><span>Warnung: Wir übernehmen keine Verantwortung für jegliche Art von Scam-Schäden!&nbsp;</span></div>
    <section class="py-5">
        <div>
        <h3 class="text-center" style="font-weight: bold;padding: 30px;">Domain-Checker</h3>
            <p class="text-center" style="font-size: 0.9rem; color: #6c757d;">Bitte eine E-Mail Adresse oder einen Link in die Suchleiste eingeben.</p><br>
        </div>
        <div class="d-flex justify-content-center">
            <form method="POST" action="domain-checker.php" class="d-flex align-items-center">
                <input type="text" name="inputField" placeholder="Enter a domain" 
                    style="width: 268px; height: 40px; border: 1px solid #ced4da; border-radius: 0.25rem; padding: 0.375rem 0.75rem; margin-right: 10px;" 
                    required>
                <button class="btn btn-primary" type="submit" 
                    style="height: 40px; border-radius: 0; border: none; background: rgba(9,113,78,0.78);">
                    Check
                </button>
            </form>
        </div>

        <div class="d-flex justify-content-center mt-3">
    <?php if (!empty($resultMessage)): ?>
        <div style="background-color: #f8f9fa; border: 1px solid #ced4da; border-radius: 0.25rem; padding: 10px; width: 50%; text-align: center;">
            <p style="font-size: 1rem; color: #212529; margin-bottom: 10px;">
                <?php echo $resultMessage; ?>
            </p>
            <?php if (strpos($resultMessage, 'nicht blacklisted') !== false): ?>
                <div style="font-size: 2rem; color: green;">✔️</div>
            <?php elseif (strpos($resultMessage, 'blacklisted') !== false || strpos($resultMessage, 'unknown source') !== false): ?>
                <div style="font-size: 2rem; color: red;">❌</div>
            <?php endif; ?>
        </div>

    <?php endif; ?>
</div>

        <div class="d-flex justify-content-center mt-3">
            <?php if (!empty($message)): ?>
                <p><?php echo $message; ?></p>
            <?php endif; ?>
        </div>
    </section>
    <script src="assets/bootstrap/js/bootstrap.min.js"></script>
    <script src="assets/js/bold-and-bright.js"></script>
</body>

</html>
