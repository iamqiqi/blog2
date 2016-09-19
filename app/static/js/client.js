/* global $ */
$(document).ready(function() {
    $('[data-toggle="popover"]').popover({
        container: "body",
        placement: "bottom",
        html: true,
        content: function() {
            return $('#popover-content').html();
        }
    });

    $('.show-post-button').on('click', function() {
        $('.new-post').slideDown('slow');
    });

    $('.hide-post').on('click', function() {
        $('.new-post').slideUp('slow');
    });

    $('.new-post-button').on('click', function() {
        var content = $('.post-content').val();
        $.ajax({
            type: 'POST',
            url: "/post",
            data: { content: content },
            success: function(res) {
                var post_id = res;
                $('<div class="alert alert-success">you posted a new post</div>')
                    .appendTo($('.message'))
                    .hide()
                    .slideDown(400, function(){
                        setTimeout(function() {
                            $('.alert').slideUp(400);
                        }, 2000);
                    });

                $('.post-content').val('');
                $('.new-post').hide();

                if (window.location.href.indexOf('/users/') > -1) {
                    var $wrapper = $('<div>');
                    var $content = $('<span>');
                    var $button = $('<button>');

                    $content.text(content);

                    $button.addClass('delete-post-button')
                        .attr('id', post_id)
                        .text('X');

                    $wrapper
                        .append($content)
                        .append($button)
                        .hide()
                        .prependTo($('.post-list'))
                        .slideDown(200);
                }
            }
        });
    });

    $(document).on('click', '.delete-post-button', function(){
        var post_id = this.id;
        var that = this;
        $.ajax({
            type: 'POST',
            url: "/deletepost",
            data: {id: post_id},
            success: function(){
                $(that).parent().remove();
                $('<div class="alert alert-success">you deleted one post!</div>').appendTo($('.message')).hide().slideDown(400, function(){
                    setTimeout(function() {
                        $('.alert').slideUp(200);
                    }, 1000);
                });
            }
        });
    });

    $('.edit-bio-button').on('click', function(){
        var content = $('.bio-content').val();
        $.ajax({
            type: 'POST',
            url: "/bio",
            data: {content: content},
            success: function(){
                $('<div class="alert alert-success">you updated your bio</div>')
                    .appendTo($('.message'))
                    .hide()
                    .slideDown(400, function() {
                        setTimeout(function() {
                            $('.alert').slideUp(400);
                        },
                        2000);
                    });

                if (content == '') {
                    $('.show-modal-button').text('Add');
                } else {
                    $('.show-modal-button').text('Edit');
                }

                $('.about-me').text(content);
                $('.bio-content').val('');
                $('.mybio').modal('hide');
            }
        });
    });

    $('.input-content').keyup(function(){
        var len = $(this).val().length;
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

    $(document).on('click', '.email-edit-btn', function() {
        $('.email-edit-form').removeClass('hide');
    });

    $(document).on('click', '.username-edit-btn', function() {
        $('.username-edit-form').removeClass('hide');
    });

    $(document).on('click', '.password-edit-btn', function() {
        $('.password-edit-form').removeClass('hide');
    });

    $(document).on('click', '.cancel-account-edit-btn', function() {
        var $parent = $(this).closest('.account-edit-form');
        var $fields = $parent.find('input');
        $fields.val('');
        var $errors = $parent.find('.error');
        $errors.text('');
        $(this).parent().addClass('hide');
    });

    $(document).on('click', '.username-update-btn', function() {
        $('.username-error').text('');
        var new_username = $('.username-edit-input').val().toLowerCase().trim();
        var old_username = $('.updated-username').text();
        if (new_username == '') {
            ($('.username-error')).prepend('<div>username can not be empty</div>');
        }
        else if (new_username != old_username) {
            $.ajax({
                type: 'POST',
                url: "/users/" + old_username + "/account/username",
                data: { new_username: new_username },
                success: function() {
                    var userlink = '<a href="/users/'+ new_username +'">' + new_username + '</a>';
                    $('.header-username').replaceWith(userlink);
                    $('.updated-username').text(new_username);
                    $('.username-edit-input').val('');
                    $('.username-edit-form').addClass('hide');
                },
                error: function(xhr, status, error) {
                    var errortext = xhr.responseText;
                    ($('.username-error')).prepend('<div>'+ errortext +'</div>');
                }
            });
        }
    });

    $(document).on('click', '.email-update-btn', function() {
        $('.email-error').text('');
        var new_email = $('.email-edit-input1').val().toLowerCase().trim();
        var new_email_confirm = $('.email-edit-input2').val().toLowerCase().trim();
        var old_email = $('.updated-email').text();
        if (new_email == '' || new_email_confirm == '') {
            ($('.email-error')).prepend('<div>all fields are required</div>');
        }
        else if (new_email != new_email_confirm) {
            ($('.email-error')).prepend('<div>please confirm your email address</div>');
        }
        else if (new_email != old_email) {
            var username = $('.updated-username').text();
            $.ajax({
                type: 'POST',
                url: "/users/" + username + "/account/email",
                data: {new_email: new_email},
                success: function(){
                    $('.updated-email').text(new_email);
                    $('.email-edit-input').val('');
                    $('.email-edit-form').addClass('hide');
                },
                error: function(xhr, status, error) {
                    var errortext = xhr.responseText;
                    ($('.email-error')).prepend('<div>'+ errortext +'</div>');
                }
            });
        }
    });

    $(document).on('click', '.password-update-btn', function() {
        $('.password-error').text('');
        var new_password = $('.password-edit-input2').val();
        var new_password_confirm = $('.password-edit-input3').val();
        var old_password = $('.password-edit-input1').val();
        if (old_password == '' || new_password == '' || new_password_confirm == '') {
            ($('.password-error')).prepend('<div>all fields are required</div>');
        }
        else if (new_password.length < 6) {
            ($('.password-error')).prepend('<div>at least 6 digits are required for a password</div>');
        }
        else if (new_password != new_password_confirm) {
            ($('.password-error')).prepend('<div>please confirm your new password</div>');
        }
        else {
            var username = $('.updated-username').text();
            $.ajax({
                type: 'POST',
                url: "/users/" + username + "/account/password",
                data: {
                    current_password: old_password,
                    new_password: new_password
                },
                success: function(){
                    $('.password-edit-input1').val('');
                    $('.password-edit-input2').val('');
                    $('.password-edit-input3').val('');
                    $('.password-edit-form').addClass('hide');
                },
                error: function(xhr, status, error) {
                    var errortext = xhr.responseText;
                    ($('.password-error')).prepend('<div>'+ errortext +'</div>');
                }
            });
        }
    });

    $(document).on('click', '.delete-account-btn', function(){
        if (confirm('Are you sure ?')) {
            var email = $('.updated-email').text();
            $.ajax({
                type: 'POST',
                url: "/deleteaccount",
                data: {email: email},
                success: function(data){
                    window.location.href = data;
                }
            });
        }
    });
});