/* global $ */
$(document).ready(function(){
    $('[data-toggle="popover"]').popover({
        container: "body",
        placement: "bottom",
        html: true,
        content: function(){
            return $('#popover-content').html()
        }
    });

    $('.new-post-button').on('click', function(){
        $('.new-post').slideDown('slow');
    });

    $('.hide-post').on('click', function(){
        $('.new-post').slideUp('slow');
    });

    $('.post-button').on('click', function(){
        var errors = [];
        var content = $('.post-content').val();
        $.ajax({
            type: 'POST',
            url: "/post",
            data: {content: content},
            success: function(){
                $('<div class="alert alert-success">you posted a new post</div>').appendTo($('.message')).hide().slideDown(400, function(){
                    setTimeout(function() {
                        $('.alert').slideUp(400);
                    }, 2000);
                });
                $('.post-content').val('');
                $('.new-post').hide();
            }
        });
    });

    $('.post-content').keyup(function(){
        var len = $(this).val().length
        if ((len < 1) || (len > 140)) {
            $('.post-button').addClass('disabled').prop('disabled', true);
        } else {
            $('.post-button').removeClass('disabled').prop('disabled', false);
        }
        $('.count').text("count: "+len);
    });

    $(document).on('click', '.show-modal-button', function() {
        $('.mybio').modal('show');
    });

    $('.mybio').on('shown.bs.modal', function() {
        $('.bio-textbox').autosize();
    });
});