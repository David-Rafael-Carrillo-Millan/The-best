(function(){
    const btnsComprarLibro = document.querySelectorAll('.btnComprarLibro')
    let isbnLibroSeleccionado = null;
    const csrf_token = document.querySelector("[name = 'csrf-token']").value;

    btnsComprarLibro.forEach((btn) => {
        btn.addEventListener('click', function(){
            isbnLibroSeleccionado = this.id;
            confirmarCompra();
        });
    });

    const confirmarCompra= () =>{

        Swal.fire({
            title: 'Confirmar la compra del libro seleccionado?',
            inputAttributes:{
                autocapitalize : 'off'
            },
            showCancelButton: true,
            confirmButtonText: 'Comprar',
            showLoaderOnConfirm: true,
            preConfirm: async()=>{
                console.log(window.origin);
                return await fetch(`${window.origin}/comprarLibro`, {
                    method : 'POST',
                    mode : 'same-origin',
                    credentials : 'same-origin',
                    headers:{
                        'Content-Type' : 'application/json',
                        'X-CSRF-TOKEN' : csrf_token
                    },
                    body: JSON.stringify({
                        'isbn' : isbnLibroSeleccionado
                    })
                }).then(response=>{
                    if(!response.ok){
                        notificacionSwal('Error', response.statusTex, 'error', 'Cerrar');
                    }
                    return response.json();
                }).then(data=>{
                    if(data.exito){
                        notificacionSwal('Éxito!', 'Libro Comprado', 'success', 'OK');
                    }else{
                        notificacionSwal('Alerta!', data.mensaje, 'warning', 'OK');
                    }
                    
                }).catch(error=>{
                    notificacionSwal('Error', error, 'error', 'Cerrar');

                });

            },
            allowOutsideClick: () => false,
            allowEscapeKey: () => false
        });


    };
    
})();