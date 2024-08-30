Per gestire l'autenticazione nel front office di un'applicazione Vue.js con un backend Laravel, devi implementare un sistema di autenticazione basato su token, generalmente utilizzando JWT (JSON Web Tokens) o OAuth. Di seguito ti fornisco una guida su come implementare l'autenticazione utilizzando JWT, che è una delle soluzioni più comuni.

### Passaggi per implementare l'autenticazione

1. **Configurazione di Laravel per l'autenticazione tramite API**

    - Assicurati di avere il package `laravel/passport` o `tymon/jwt-auth` installato, che sono i più comuni per gestire l'autenticazione API. Per questa guida, utilizzerò `tymon/jwt-auth`.

    - Installa il package:
        ```bash
        composer require tymon/jwt-auth
        ```
    - Pubblica il file di configurazione e genera la chiave segreta:
        ```bash
        php artisan vendor:publish --provider="Tymon\JWTAuth\Providers\LaravelServiceProvider"
        php artisan jwt:secret
        ```
    - Configura le rotte per l'autenticazione nel tuo `routes/api.php`:
        ```php
        Route::post('login', [AuthController::class, 'login']);
        Route::post('register', [AuthController::class, 'register']);
        Route::middleware('auth:api')->group(function () {
            Route::post('logout', [AuthController::class, 'logout']);
            Route::get('user', [AuthController::class, 'me']);
        });
        ```

2. **Creazione del `AuthController` in Laravel**

    - Genera un controller per gestire l'autenticazione:
        ```bash
        php artisan make:controller AuthController
        ```
    - Implementa i metodi per `login`, `register`, `logout` e `me`:

        ```php
        use Illuminate\Support\Facades\Auth;
        use App\Models\User;
        use Illuminate\Http\Request;
        use Tymon\JWTAuth\Facades\JWTAuth;
        use Tymon\JWTAuth\Exceptions\JWTException;

        class AuthController extends Controller
        {
            public function register(Request $request)
            {
                $this->validate($request, [
                    'name' => 'required|string|max:255',
                    'email' => 'required|string|email|max:255|unique:users',
                    'password' => 'required|string|min:6|confirmed',
                ]);

                $user = User::create([
                    'name' => $request->name,
                    'email' => $request->email,
                    'password' => bcrypt($request->password),
                ]);

                $token = JWTAuth::fromUser($user);

                return response()->json(compact('user', 'token'), 201);
            }

            public function login(Request $request)
            {
                $credentials = $request->only('email', 'password');

                try {
                    if (! $token = JWTAuth::attempt($credentials)) {
                        return response()->json(['error' => 'Invalid credentials'], 400);
                    }
                } catch (JWTException $e) {
                    return response()->json(['error' => 'Could not create token'], 500);
                }

                return response()->json(compact('token'));
            }

            public function logout()
            {
                Auth::logout();
                return response()->json(['message' => 'Successfully logged out']);
            }

            public function me()
            {
                return response()->json(Auth::user());
            }
        }
        ```

3. **Gestione dell'autenticazione nel Front Office con Vue.js**

    - **Installazione Axios**: Se non l'hai già fatto, assicurati di avere Axios installato nel tuo progetto Vue.js per gestire le richieste HTTP.
        ```bash
        npm install axios
        ```
    - **Login e Salvataggio del Token**: Implementa una funzione di login nel componente Vue.js che invia le credenziali all'API e salva il token JWT in `localStorage` o `sessionStorage`.

        ```javascript
        methods: {
            async login() {
                try {
                    const response = await axios.post('http://laravel-api.test/api/login', {
                        email: this.email,
                        password: this.password
                    });

                    const token = response.data.token;
                    localStorage.setItem('token', token);
                    axios.defaults.headers.common['Authorization'] = `Bearer ${token}`;

                    // Reindirizza l'utente dopo il login
                    this.$router.push('/dashboard');
                } catch (error) {
                    console.error("Invalid credentials:", error);
                }
            }
        }
        ```

    - **Protezione delle Rotte Autenticate**: Configura Vue Router per proteggere le rotte che richiedono autenticazione.

        ```javascript
        const router = new VueRouter({
            routes: [
                {
                    path: "/dashboard",
                    component: Dashboard,
                    meta: { requiresAuth: true },
                },
                // altre rotte...
            ],
        });

        router.beforeEach((to, from, next) => {
            const token = localStorage.getItem("token");
            if (
                to.matched.some((record) => record.meta.requiresAuth) &&
                !token
            ) {
                next("/login");
            } else {
                next();
            }
        });
        ```

    - **Gestione del Logout**: Quando l'utente fa logout, rimuovi il token dallo storage e reindirizza l'utente.
        ```javascript
        methods: {
            logout() {
                localStorage.removeItem('token');
                delete axios.defaults.headers.common['Authorization'];
                this.$router.push('/login');
            }
        }
        ```

4. **Rinnovo e Verifica del Token**
    - **Rinnovo Automatico**: Puoi implementare il rinnovo automatico del token prima della sua scadenza utilizzando un'intercettazione di Axios.
    - **Gestione degli Errori di Autenticazione**: Se il token è scaduto, gestisci l'errore e reindirizza l'utente alla pagina di login.

### Conclusione

Seguendo questi passaggi, sarai in grado di gestire l'autenticazione nel front office della tua applicazione Vue.js utilizzando un backend Laravel. L'uso di JWT ti permette di mantenere l'utente autenticato in modo sicuro e di proteggere le rotte del tuo front office.
