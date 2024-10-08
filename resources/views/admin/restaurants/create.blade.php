{{-- @extends('layouts.admin')

@section('content')
    <div class="container">
        <h1 class="text-center py-2">Crea Nuovo Ristorante</h1>
        <div>
            @if ($errors->any())
                <div class="alert alert-danger">
                    <ul>
                        @foreach ($errors->all() as $error)
                            <li>{{ $error }}</li>
                        @endforeach
                    </ul>
                </div>
            @endif
        </div>

        <form method="POST" action="{{ route('admin.restaurants.store') }}" enctype="multipart/form-data">
            @csrf

            <div class="mb-3">
                <label for="name" class="form-label">Nome Ristorante</label>
                <input type="text" class="form-control" name="name" value="{{ old('name') }}" min="4"
                    max="255" required>
                @error('name')
                    <div class="form-text text-danger">{{ $message }}</div>
                @enderror
            </div>

            <div class="mb-3">
                <label for="address" class="form-label">Indirizzo</label>
                <input type="text" class="form-control" name="address" value="{{ old('address') }}" min="4"
                    max="255" required>
                @error('address')
                    <div class="form-text text-danger">{{ $message }}</div>
                @enderror
            </div>

            <div class="mb-3">
                <label for="tax_id" class="form-label">P.Iva</label>
                <input type="text" class="form-control" name="tax_id" value="{{ old('tax_id') }}" min="4"
                    max="255" required>
                @error('tax_id')
                    <div class="form-text text-danger">{{ $message }}</div>
                @enderror
            </div>

            <div class="mb-3">
                <label for="img" class="form-label"></label>
                <input type="file" class="form-control" name="img" value="{{ old('img') }}" required
                    accept=".png, .jpg, .jpeg">
                @error('img')
                    <div class="form-text text-danger">{{ $message }}</div>
                @enderror
            </div>

            @foreach ($categories as $item)
                <label for="category_id" class="form-label">{{ $item->name }}</label>
                <input type="checkbox" class="form-check-input" name="category_id[]" value="{{ $item->id }}">
            @endforeach
            @error('category_id')
                <div class="form-text text-danger">{{ $message }}</div>
            @enderror


            <button type="submit" class="btn btn-outline-primary">Invia Nuovo Progetto</button>
        </form>
    </div>
@endsection --}}
