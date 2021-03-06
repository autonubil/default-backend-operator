<html>
	<head>
		<title>Wallaby</title>
		<meta charset="UTF-8" />
		<meta name="description" content="Autogenerated Jump Page for K8s Clusters" />
		<meta name="keywords" content="Ingress,k8s,service" />
		<meta name="author" content="autonubil System GmbH" />
		<meta name="viewport" content="width=device-width, initial-scale=1.0" />

		<!-- Material Design -->
		<link rel="stylesheet" href="https://fonts.googleapis.com/icon?family=Material+Icons" />
		<link rel="stylesheet" href="https://code.getmdl.io/1.3.0/material.teal-blue.min.css" />
		<script defer src="https://code.getmdl.io/1.3.0/material.min.js"></script>

		<script src="https://cdnjs.cloudflare.com/ajax/libs/dialog-polyfill/0.4.10/dialog-polyfill.min.js"></script>
		<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/dialog-polyfill/0.4.10/dialog-polyfill.min.css" />

		<!-- sentry -->
		<script src="https://cdn.ravenjs.com/3.26.4/raven.min.js" crossorigin="anonymous"></script>

		<script>
			Raven
				.config('https://d874aba1115344319f21322520e53fb3@sentry.plexus.autonubil.net/3')
				.install();
		</script>

		<style>
			.wallaby-layout {
			}
			.wallaby-layout .mdl-layout__header,
			.wallaby-layout .mdl-layout__drawer-button {
			}

			.mdl-card {
				width: 200px;
				margin: 15px;

			}

			.wallaby-card > .mdl-card__title {
				background-color: #ddd;
				width: 200px;
				height: 200px;
				z-index: 20;
			}
			.wallaby-card > .mdl-card__menu {
			}

			.wallaby-card > .mdl-card__actions {
				min-height: 90px;
				background-color: #eaeaea;
			}

			.wallaby-card > mdl-card__title-text {
				position: absolute;
				bottom: 10px;
				z-index: 20;
			}
			.wallaby-card > .mdl-card__supporting-text {
				background-color: #fafafa;
				min-height: 75px;
			}

			h2 {
				font-size: 20px;
				text-align: center;
			}

			.bkgndImg {
				position: absolute;
				left: 0px;
				top: 7px;
				height: 200px;
				width: 200px;
				text-align: center;
				align-items: center;
				z-index: 1;
			}

			a {
				text-decoration: none;
			}

			a.img {
				position: relative;
				display: block;
				margin-left: auto;
				margin-right: auto;
				max-height: 140px;
			}

			img.icon {
				max-width: 90px;
				max-height: 90px;
				border: 10px;
				#border-radius: 180px;
				background-color: transparent;
			}

			img.overlay {
				background: #ffffffa3;
				-moz-border-radius: 25px;
				-webkit-border-radius: 25px;
				border-radius: 25px;

				width: 40px;
				height: 40px;
				position: absolute;
				top: 50px;
				right: 40px;
			}
			dialog {
				border: 1px solid rgba(0, 0, 0, 0.3);
				border-radius: 6px;
				box-shadow: 0 3px 7px rgba(0, 0, 0, 0.3);
			}
		</style>

		<script>
	 	function showInfo(info) {
			var dialog = document.querySelector('dialog');
			document.querySelector('#appNotice').innerHTML=info;
			if (! dialog.showModal) {
				dialogPolyfill.registerDialog(dialog);
			}
			dialog.showModal();
			dialog.querySelector('.close').addEventListener('click', function() {
				dialog.close();
			});
		 }
	</script>

	</head>
	<body>
		<dialog class="mdl-dialog--wide">
			<h4 class="mdl-dialog__title">Application Info</h4>
			<div class="mdl-dialog__content">
			<pre id="appNotice">
			</pre>
			</div>
			<div class="mdl-dialog__actions">
			<button type="button" class="mdl-button close">Close</button>
			</div>
		</dialog>

		<div class="wallaby-layout mdl-layout mdl-js-layout">
			<header class="mdl-layout__header mdl-layout__header">
				<div class="mdl-layout__header-row">
					<!-- Title -->
					<img src="static/wallaby.svg" width="50" heigth="50" style="border-radius: 50px;"/>&nbsp;
					<span class="mdl-layout-title">Wallaby</span>
					<!-- Add spacer, to align navigation to the right -->
					<div class="mdl-layout-spacer"></div>
					<!-- Navigation -->
					{{- if .Claims }}
					<nav class="mdl-navigation">
					{{- if .Claims.Email }}
						<img title="{{ .Claims.Name  }}" src="https://www.gravatar.com/avatar/{{.Claims.Email | lower | md5sum }}?s=50&d=identicon" style="border-radius: 50px;" />&nbsp;
						{{- if .OidcConfig.LogoutURL }}
							<a class="mdl-navigation__link" href="{{ .OidcConfig.LogoutURL }}">
								<button class="mdl-button mdl-js-button mdl-button--icon" alt="logout">
										<i class="material-icons">exit_to_app</i>
								</button>
							</a>
						{{- end }}
					{{- end }}
					</nav>
					{{- else }}
						{{- if .OidcConfig.LoginURL }}
						<nav class="mdl-navigation">
							<a class="mdl-navigation__link" href="{{ .OidcConfig.LoginURL }}">
								<button class="mdl-button mdl-js-button mdl-button--icon" alt="authenticate">
										<i class="material-icons">vpn_key</i>
								</button>
							</a>
						</nav>
						{{- end }}
					{{- end }}
				</div>
			</header>
			<main class="mdl-layout__content">
				<div class="mdl-grid">
					{{ range $svc := .Services  }}
						<div class="wallaby-card mdl-card mdl-shadow--4dp" title="{{ $svc.Description }}">
							<div class="mdl-card__title">
								{{- if $svc.Icon }}
								<span class="bkgndImg">
									<a class="img" href="{{ $svc.URL }}" target="{{ $svc.ID }}"><img class="icon" src="{{ $svc.Icon }}" onerror="this.style.display='none'">
									<br/>
									{{- if $svc.Overlay }}
									<img class="overlay" src="{{ $svc.Overlay }}" ng-if="item.overlay"/>
									{{- end }}
									</a>
								</span>
								{{- end }}
								<h2  title="{{ $svc.URL }}" class="mdl-card__title-text" style="z-index: 100;" ><a class="img" href="{{ $svc.URL }}" target="{{ $svc.ID }}">{{ $svc.Name | replace "-" " " | title }}</a></h2>
							</div>
							<div id="element-{{ $svc.ID }}" style="display:none">

								<div class="mdl-card__supporting-text">
								<b>{{ $svc.Name | replace "-" " " | title }}</b><br/>
								{{ $svc.URL }}<br/>
								{{- if $svc.Description }}
									{{ $svc.Description }}<br/>
								{{- end }}
								</div>

									{{- if $svc.Info }}
									<pre>{{ $svc.Info }}</pre>
									{{- end }}


									<div class="mdl-grid">
									{{- if $svc.Visibility }}
										<span class="mdl-chip" title="Network visibility: {{ $svc.Visibility }}">
											<span  class="material-icons mdl-chip__contact">{{ if eq $svc.Visibility "public" }}public{{ else }}vpn_lock{{ end }}</span>
											<span class="mdl-chip__text">{{ $svc.Visibility }}</span>
										</span>
									{{- end }}

									{{- if $svc.Namespace }}
										<span class="mdl-chip" title="Namespace: {{ $svc.Namespace }}">
											<span  class="material-icons mdl-chip__contact">folder</span>
											<span class="mdl-chip__text">{{ $svc.Namespace }}</span>
										</span>
									{{- end }}


									{{- if $svc.ChartName }}
										<span class="mdl-chip" title="Helm Chart: {{ $svc.ChartName }}-{{ $svc.ChartVersion }}" >
											<span  class="material-icons mdl-chip__contact">table_chart</span>
											<span class="mdl-chip__text">{{ $svc.ChartName }}</span>
										</span>
									{{- end }}

									{{- if $svc.Application }}
										<span class="mdl-chip" title="Application: {{ $svc.Application }}">
											<span  class="material-icons mdl-chip__contact">apps</span>
											<span class="mdl-chip__text">{{ $svc.Application }}</span>
										</span>
									{{- end }}

									{{- range $tagId, $tag := $svc.Tags  }}
										<span class="mdl-chip">
											<span class="mdl-chip__text">{{ $tag }}</span>
										</span>
									{{- end }}
								</div>
							</div>
							<div class="mdl-card__menu" style="z-index: 30;">
								<button class="mdl-button mdl-button--icon mdl-js-button mdl-js-ripple-effect" onclick="javascript:showInfo(document.getElementById('element-{{ $svc.ID }}').innerHTML)">
									<i class="material-icons">notes</i>
								</button>
							</div>

					</div>
					{{ end }}
				</div>
				<!--
				<pre>{{ .OidcConfig | toPrettyJson }}
				<pre>{{ .Claims | toPrettyJson }}
				</pre>
-->
			</main>
			<footer class="mdl-mini-footer">
				<span>&copy; 2019 by <a href="http://autonubil.com/">autonubil System GmbH</a></span>&nbsp;&nbsp;
				<a href="http://autonubil.com/#impressum">Privacy & Terms</a>
			</footer>
		</div>
	</body>
</html>
