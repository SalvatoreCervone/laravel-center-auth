<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('center_auth_clients', function (Blueprint $table): void {
            $table->id();
            $table->string('client_id')->unique();
            $table->string('name');
            $table->text('description')->nullable();
            $table->string('callback_url');
            $table->string('secret_hash');
            $table->string('previous_secret_hash')->nullable();
            $table->timestamp('previous_secret_expires_at')->nullable();
            $table->boolean('is_active')->default(true)->index();
            $table->timestamp('last_used_at')->nullable();
            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('center_auth_clients');
    }
};
