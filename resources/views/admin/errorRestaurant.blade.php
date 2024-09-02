@extends('layouts.admin')

@section('content')
	<div class="container-fluid mt-4">
		<div class="row justify-content-center">
			<div class="col-md-8">
				<div class="card">
					<div class="card-header">{{ __('Dashboard') }}</div>

					<div class="card-body">
						@if (session('status'))
							<div class="alert alert-success" role="alert">
								{{ session('status') }}
							</div>
						@endif

						@if ($status)
							<div class="alert alert-danger" role="alert">
								{{ $status }}
							</div>
						@endif

						{{ __('You are logged in!') }} <br>

						<h2>Il tuo ristorante :</h2>
						<h1>{{ Auth::user()->restaurant->name }}</h1>
					</div>
				</div>
			</div>
		</div>
	</div>
@endsection
