<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\Models\Category;
use App\Models\Restaurant;
use App\Models\User;
use App\Providers\RouteServiceProvider;
use Illuminate\Auth\Events\Registered;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Storage;
use Illuminate\Validation\Rules;
use Illuminate\View\View;
use Illuminate\Support\Str;

class RegisteredUserController extends Controller
{
    /**
     * Display the registration view.
     */
    public function create(): View
    {
        $data = [
            'categories' => Category::all()
        ];
        return view('auth.register', $data);
    }

    /**
     * Handle an incoming registration request.
     *
     * @throws \Illuminate\Validation\ValidationException
     */
    public function store(Request $request): RedirectResponse
    {
        $validated =
            $request->validate([
                'name' => ['required', 'string', 'max:255'],
                'email' => ['required', 'string', 'email', 'max:255', 'unique:' . User::class],
                'password' => ['required', 'confirmed', Rules\Password::defaults()],
                // valido i dati del ristorante
                'restaurant_name' => ['required', 'string', 'max:255'],
                'restaurant_address' => ['required', 'string', 'max:255'],
                'restaurant_tax_id' => ['required', 'string', 'max:255'],
                'category_id' => ['required', 'array'],
                'category_id.*' => ['required', 'numeric', 'integer', 'exists:categories,id'],
                'restaurant_img' => ['image']
            ]);

        $user = User::create([
            'name' => $validated['name'],
            'email' => $validated['email'],
            'password' => Hash::make($validated['password']),
        ]);


        event(new Registered($user));

        Auth::login($user);

        // Creo un nuovo ristorante dopo che l'utente e' loggato

        $newRestaurant = new Restaurant();
        if (isset($validated['restaurant_img'])) {
            $img = Storage::put('uploads', $validated['restaurant_img']);
            $validated['restaurant_img'] = $img;  //salvo il percorso
            $newRestaurant->img = $validated['restaurant_img'];
        }

        $newRestaurant->name = $validated['restaurant_name'];
        $newRestaurant->address = $validated['restaurant_address'];
        $newRestaurant->tax_id = $validated['restaurant_tax_id'];
        $newRestaurant->slug = Str::slug($validated['restaurant_name']);
        $newRestaurant->user_id = Auth::user()->id;
        $newRestaurant->save();
        $newRestaurant->categories()->sync($validated['category_id']);

        return redirect(RouteServiceProvider::HOME);
    }
}
