# EASY AUTH

Easy Auth for User Meta Database Login Session Storage

## Small Notes

```php
<?php
namespace ExampleApp;

use Apatis\Auth\Easy\AuthCookie;
use Apatis\Auth\Easy\SessionToken;

require __DIR__ . '/vendor/autoload.php';

/**
 * @var array $sessionDataFromDatabase meta
 * or get from (array) database->get(selector_from_database where username)
 */
$sessionDataFromDatabase = [];
$cookieExpiration        = strtotime('+1 year');
$secretKey               = 'secret';
$username                = 'username';
$password                = 'password';
$cookieName              = 'cookie_name_selector';
$sessionToken            = new SessionToken($sessionDataFromDatabase);
$authCookie              = new AuthCookie($secretKey, true);

/**
 * Token to save on session and for generated auth cookie
 */
$token = $sessionToken->create($cookieExpiration);
/**
 * Generated Cookie Values to set for cookies
 */
$cookieValue = $authCookie->generate(
    $username,
    $password,
    $cookieName,
    $token
);

if (setcookie($cookieName, $cookieValue, $cookieExpiration)) {
    // doing database save
    /**
     * Database->save(json_encode($sessionToken));
     * or just serialize t save as blob or safe value
     * Database->save(serialize($sessionToken));
     */
}

/**
 * To get Data from cookie
 */
$cookieStoredValues = isset($_COOKIE[$cookieName]) ? $_COOKIE[$cookieName] : null;
$isLogged = false;
if (is_string($cookieStoredValues)) {
    if (is_array($cookieToken = $authCookie->parse($cookieStoredValues))) {
        $generator = $authCookie->getGenerator();
        $username = $cookieToken[$generator::USERNAME_KEY];   
        // $token    = $cookieToken[$generator::TOKEN_KEY];
        // .... @see \Apatis\Auth\Easy\Generator::parse();
        // $userData = Database->getUserByUsername($username); << example
        /**
         * @var array $userData array detail 
         */
        if (!empty($userData)) {
            $tokenForSessionDB = $authCookie->validate(
                (string) $userData['username'],
                (string) $userData['password'],
                $cookieName,
                $cookieStoredValues
            );
            // $tokenForSessionDB is string
            if ($tokenForSessionDB !== false) {
                // @var bool $isLogged
                $isLogged =  $sessionToken->verify($tokenForSessionDB);
            }
        }
    }
}

if ($isLogged) {
    // do logged
}

```