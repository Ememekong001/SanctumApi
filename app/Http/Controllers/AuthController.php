<?php

namespace App\Http\Controllers;

use App\Http\Requests\LoginRequest;
use App\Http\Requests\REgisterRequest;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;

class AuthController extends BaseController
{
    public function register(REgisterRequest $request)
    {
        $validated = $request->validated();

        $user = User::create([
            'name' => $validated['name'],
            'email' =>$validated['email'],
            'password' =>Hash::make($validated['password']),
        ]);
        return $this->sendReply($user, 'User Registered Successfully');
    }

    public function login(LoginRequest $request)
    {
        $credentials = $request->only('email', 'password');
        if (!Auth::attempt($credentials))
        {
            return $this->sendError('Unauthorised.', ['error'=>'Unauthorised']);
        }
        $authUser = User::where('email', $request['email'])->firstOrFail();

        $token = $authUser->createToken('auth_token')->plainTextToken;

        return $this->sendResponse($token, $authUser, 'User logged in Successfully');
    }

    public function logout()
    {
        $user = Auth::logout();
        return $this->sendReply($user,'Users logged out successfully');
    }
}
